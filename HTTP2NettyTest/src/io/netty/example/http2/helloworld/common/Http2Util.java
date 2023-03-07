package io.netty.example.http2.helloworld.common;

import static io.netty.handler.logging.LogLevel.INFO;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPipeline;
import io.netty.example.http2.helloworld.client.Http2ClientResponseHandler;
import io.netty.example.http2.helloworld.client.Http2SettingsHandler;
import io.netty.example.http2.helloworld.server.Http2ServerResponseHandler;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpScheme;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.codec.http2.DefaultHttp2Connection;
import io.netty.handler.codec.http2.DelegatingDecompressorFrameListener;
import io.netty.handler.codec.http2.Http2Connection;
import io.netty.handler.codec.http2.Http2FrameCodecBuilder;
import io.netty.handler.codec.http2.Http2FrameLogger;
import io.netty.handler.codec.http2.Http2SecurityUtil;
import io.netty.handler.codec.http2.HttpConversionUtil;
import io.netty.handler.codec.http2.HttpToHttp2ConnectionHandler;
import io.netty.handler.codec.http2.HttpToHttp2ConnectionHandlerBuilder;
import io.netty.handler.codec.http2.InboundHttp2ToHttpAdapterBuilder;
import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.ApplicationProtocolConfig.Protocol;
import io.netty.handler.ssl.ApplicationProtocolConfig.SelectedListenerFailureBehavior;
import io.netty.handler.ssl.ApplicationProtocolConfig.SelectorFailureBehavior;
import io.netty.handler.ssl.ApplicationProtocolNames;
import io.netty.handler.ssl.ApplicationProtocolNegotiationHandler;
import io.netty.handler.ssl.OpenSsl;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import io.netty.handler.ssl.SupportedCipherSuiteFilter;

public class Http2Util {
    public static final int PORT = 8443;
    public static final String HOST = "127.0.0.1";
    public static final boolean FIPS = true; 
    static String alias = "server1";
    static String password = "changeit_server";
    static char[] keyStorePassword = password.toCharArray();
    static SslProvider provider = OpenSsl.isAlpnSupported() ? SslProvider.OPENSSL : SslProvider.JDK;
    static char[] trustStorePassword = "changeit_server".toCharArray();

    public static SslContext createSSLContext(boolean isServer) throws Exception {
        Security.setProperty("FIPS_MODE", "true");
        Provider[] providers = Security.getProviders();
        if (providers != null && providers.length > 0) {
            for(int i = 0; i < providers.length; i++ ) {
                Security.removeProvider(providers[i].getName());
            }
        }
        Security.insertProviderAt(new BouncyCastleFipsProvider(), 1);
        Security.insertProviderAt(new BouncyCastleJsseProvider(FIPS), 2);
        
        System.setProperty("ssl.KeyManagerFactory.algorithm", "PKIX");
        System.setProperty("ssl.TrustManagerFactory.algorithm", "PKIX");
        System.setProperty("keystore.type", "BCFKS");
        System.setProperty("javax.net.ssl.trustStore", "NONE");
        System.setProperty("javax.net.debug", "all");


        SslContext sslCtx;
        
        System.out.println("KeyStore.getDefaultType=>"+KeyStore.getDefaultType());
        System.out.println("KeyStore.getProviders=>"+Arrays.toString(Security.getProviders()));
        
        if (isServer) {
            //SelfSignedCertificate ssc = new SelfSignedCertificate();
            KeyStore keystore = getServerKeyStore();
            
            X509Certificate cert = (X509Certificate) keystore.getCertificate(alias);
            PrivateKey key = (PrivateKey)keystore.getKey(alias, keyStorePassword);
            
            sslCtx = SslContextBuilder.forServer(getKeyManager()).sslProvider(provider)
                    .ciphers(Http2SecurityUtil.CIPHERS, SupportedCipherSuiteFilter.INSTANCE)
                    .applicationProtocolConfig(new ApplicationProtocolConfig(Protocol.ALPN, SelectorFailureBehavior.NO_ADVERTISE,
                            SelectedListenerFailureBehavior.ACCEPT, ApplicationProtocolNames.HTTP_2,
                            ApplicationProtocolNames.HTTP_1_1))
                    .build();
        } else {
            sslCtx = SslContextBuilder.forClient()
                    .sslProvider(provider/*SslProvider.JDK*/)
                    .sslContextProvider(Security.getProvider(BouncyCastleJsseProvider.PROVIDER_NAME))
//                    .keyManager(KeyManagerFactory.getInstance("PKIX", "BCJSSE"))
                    .ciphers(Http2SecurityUtil.CIPHERS, SupportedCipherSuiteFilter.INSTANCE)
                    .trustManager(getTrustManager()/*InsecureTrustManagerFactory.INSTANCE*/)
                    .applicationProtocolConfig(new ApplicationProtocolConfig(Protocol.ALPN, SelectorFailureBehavior.NO_ADVERTISE,
                            SelectedListenerFailureBehavior.ACCEPT, ApplicationProtocolNames.HTTP_2,
                            ApplicationProtocolNames.HTTP_1_1))
                    .build();

        }
        return sslCtx;

    }

    private static KeyManagerFactory getKeyManager() throws Exception {
        System.out.println("Load getKeyManager: "+provider);
        String path = "server1.ks";
        KeyManagerFactory factory = KeyManagerFactory.getInstance("X509", "BCJSSE");
       // KeyManagerFactory factory = KeyManagerFactory.getInstance("SunX509", "SunJSSE");

        File file = new File(path);
        FileInputStream is = new FileInputStream(file);
        KeyStore keyStore = KeyStore.getInstance("BCFKS");
        keyStore.load(is, keyStorePassword);
        factory.init(keyStore, keyStorePassword);
        return factory;
    }

    public static KeyStore getServerKeyStore() throws Exception{
        System.out.println("Load getKeyStore: "+provider);
        String path = "server1.ks";
        
        File file = new File(path);
        FileInputStream is = new FileInputStream(file);
        KeyStore keystore = KeyStore.getInstance("BCFKS");
        keystore.load(is, keyStorePassword);   
        return keystore;
    }

    public static TrustManagerFactory getTrustManager() throws Exception{
        System.out.println("Load trustStore: "+provider);
        String path = "server1.ks";
        System.out.println("trustStore Algorithm:"+TrustManagerFactory.getDefaultAlgorithm());
        TrustManagerFactory factory = TrustManagerFactory.getInstance("X509", "BCJSSE");
        //TrustManagerFactory factory = TrustManagerFactory.getInstance("SunX509", "SunJSSE");
        //TrustManagerFactory factory = TrustManagerFactory.getInstance("X509", "SunJSSE");
        File file = new File(path);
        FileInputStream is = new FileInputStream(file);
        KeyStore keyStore = KeyStore.getInstance("BCFKS");
        keyStore.load(is, trustStorePassword);
        factory.init(keyStore);
        return factory;           
    }

    
    public static ApplicationProtocolNegotiationHandler getServerAPNHandler() {
        ApplicationProtocolNegotiationHandler serverAPNHandler = new ApplicationProtocolNegotiationHandler(
                ApplicationProtocolNames.HTTP_1_1) {

            @Override
            protected void configurePipeline(ChannelHandlerContext ctx, String protocol) throws Exception {
                
                if (ApplicationProtocolNames.HTTP_2.equals(protocol)) {
                    ctx.pipeline().addLast(Http2FrameCodecBuilder.forServer().build(), new Http2ServerResponseHandler());
                    return;
                }
                throw new IllegalStateException("Protocol: " + protocol + " not supported");
            }
        };
        return serverAPNHandler;

    }

    public static ApplicationProtocolNegotiationHandler getClientAPNHandler(int maxContentLength,
            Http2SettingsHandler settingsHandler, Http2ClientResponseHandler responseHandler) {
        final Http2FrameLogger logger = new Http2FrameLogger(INFO, Http2Util.class);
        final Http2Connection connection = new DefaultHttp2Connection(false);

        HttpToHttp2ConnectionHandler connectionHandler = new HttpToHttp2ConnectionHandlerBuilder()
                .frameListener(
                        new DelegatingDecompressorFrameListener(connection, new InboundHttp2ToHttpAdapterBuilder(connection)
                                .maxContentLength(maxContentLength).propagateSettings(true).build()))
                .frameLogger(logger).connection(connection).build();

        ApplicationProtocolNegotiationHandler clientAPNHandler = new ApplicationProtocolNegotiationHandler(
                ApplicationProtocolNames.HTTP_1_1) {
            @Override
            protected void configurePipeline(ChannelHandlerContext ctx, String protocol) {
                if (ApplicationProtocolNames.HTTP_2.equals(protocol)) {
                    ChannelPipeline p = ctx.pipeline();
                    p.addLast(connectionHandler);
                    p.addLast(settingsHandler, responseHandler);
                    return;
                }
                ctx.close();
                throw new IllegalStateException("Protocol: " + protocol + " not supported");
            }
        };
        return clientAPNHandler;

    }

    public static FullHttpRequest createGetRequest(String host, int port) {
        FullHttpRequest request = new DefaultFullHttpRequest(HttpVersion.valueOf("HTTP/2.0"), HttpMethod.GET, "/",
                Unpooled.EMPTY_BUFFER);
        request.headers().add(HttpHeaderNames.HOST, new String(host + ":" + port));
        request.headers().add(HttpConversionUtil.ExtensionHeaderNames.SCHEME.text(), HttpScheme.HTTPS);
        request.headers().add(HttpHeaderNames.ACCEPT_ENCODING, HttpHeaderValues.GZIP);
        request.headers().add(HttpHeaderNames.ACCEPT_ENCODING, HttpHeaderValues.DEFLATE);
        return request;
    }
}