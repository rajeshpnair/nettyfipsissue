package io.netty.example.http2.helloworld.client;

import java.util.concurrent.TimeUnit;

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.example.http2.helloworld.common.Http2Util;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.ssl.SslContext;

public class Http2Client {

    public static void main(String[] args) throws Exception {
        System.out.println("Http2Client start...");
        EventLoopGroup workerGroup = new NioEventLoopGroup();
        SslContext sslCtx = Http2Util.createSSLContext(false);

        Http2ClientInitializer initializer = new Http2ClientInitializer(sslCtx, Integer.MAX_VALUE, Http2Util.HOST,
                Http2Util.PORT);

        try {
            // Configure the client.
            Bootstrap b = new Bootstrap();
            b.group(workerGroup);
            b.channel(NioSocketChannel.class);
            b.option(ChannelOption.SO_KEEPALIVE, true);
            b.remoteAddress(Http2Util.HOST, Http2Util.PORT);
            b.handler(initializer);

            // Start the client.
            Channel channel = b.connect().syncUninterruptibly().channel();
            System.out.println("Connected to ->[" + Http2Util.HOST + ':' + Http2Util.PORT + ']');

            // Wait for the HTTP/2 upgrade to occur.
            Http2SettingsHandler http2SettingsHandler = initializer.getSettingsHandler();
            http2SettingsHandler.awaitSettings(30, TimeUnit.SECONDS);

            Http2ClientResponseHandler responseHandler = initializer.getResponseHandler();
            int streamId = 3;

            FullHttpRequest request = Http2Util.createGetRequest(Http2Util.HOST, Http2Util.PORT);
            responseHandler.put(streamId, channel.write(request), channel.newPromise());
            channel.flush();

            responseHandler.awaitResponses(30, TimeUnit.SECONDS);

            System.out.println("Finished HTTP/2 request(s)");

            // Wait until the connection is closed.
            channel.close().syncUninterruptibly();
        } finally {
            workerGroup.shutdownGracefully();
        }
    }
}
