import java.io.IOException;
import java.net.Socket;

/**
 * An SSL client implemented using JSSE SSLEngine
 * @author Jon Siwek
 */
public class SSLConnectionClient extends SSLConnection {
    private static final String NET_DEBUG_MODE = "ssl";
    private static final boolean debug = true;

    /**
     * Default constructor create SSL engine
     * @throws Exception on failure to create SSL engine from key/trust material
     */
    public SSLConnectionClient() throws Exception {
        this(DEFAULT_PROTOCOLS);
    }

    public SSLConnectionClient(String[] protocols) throws Exception {
        super();
        engine.setUseClientMode(true);
        engine.setEnabledProtocols(protocols);
        // OpenSSL interop requires this.
        // See http://java.sun.com/j2se/1.4.2/relnotes.html#security
        System.setProperty("com.sun.net.ssl.rsaPreMasterSecretFix", "true");
    }

    /**
     * Connects to specified host and port
     * @param host desired hostname of peer
     * @param port desired port of peer
     * @throws IOException when socket fails to connect
     */
    public void connect(String host, int port) throws IOException {
        socket = new Socket(host, port);
    }

    /**
     * Connects to the default host/port
     * @throws IOException when socket fails to connect
     */
    public void connect() throws IOException {
        connect(DEFAULT_HOST, DEFAULT_PORT);
    }


    public static void main(String[] args) throws Exception {
        if (debug) {
            System.setProperty("javax.net.debug", NET_DEBUG_MODE);
        }

        SSLConnectionClient client = new SSLConnectionClient();

        client.connect();

        client.sendToken("hello world".getBytes());

        /*
        byte[] buf = new byte[1000000];

        for (int i = 0; i < buf.length; ++i) {
            buf[i] = 'x';
        }

        client.sendToken(buf);
        */

        client.close();
    }
}
