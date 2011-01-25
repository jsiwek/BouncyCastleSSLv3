import java.io.IOException;
import java.net.ServerSocket;

/**
 * An SSL Server implemented using JSSE SSLEngine
 * @author Jon Siwek
 */
public class SSLConnectionServer extends SSLConnection {
    private static final String NET_DEBUG_MODE = "ssl";
    private static final boolean debug = true;
   private ServerSocket serverSocket;

    /**
     * Default constructor creates SSL engine and a socket bound to default port
     * @throws Exception on failure to create SSL engine from key/trust material
     * or when socket fails to bind or accept connection
     */
    public SSLConnectionServer() throws Exception {
        this(DEFAULT_PROTOCOLS, false);
    }

    public SSLConnectionServer(String[] protocols) throws Exception {
        this(protocols, false);
    }

    public SSLConnectionServer(boolean clientAuth) throws Exception {
        this(DEFAULT_PROTOCOLS, clientAuth);
    }

    /**
     * A constructor to create the SSL engine in server mode
     * @param protocols the TLS/SSL protocol version to use
     * @param clientAuth whether to authenticate the client
     * @throws Exception on failure to create SSL engine from key/trust material
     */
    public SSLConnectionServer(String[] protocols, boolean clientAuth)
            throws Exception {
        super();
        engine.setUseClientMode(false);
        engine.setNeedClientAuth(clientAuth);
        engine.setEnabledProtocols(protocols);
    }

    /**
     * Binds he server to the given port and accepts a connection
     * @throws Exception on failure to bind or accept connection
     * @param port the port number to bind to and listen on
     */
    public void accept(int port) throws Exception {
        serverSocket = new ServerSocket(port);
        System.out.println("Waiting for connection.");
        socket = serverSocket.accept();
    }

    public void accept() throws Exception {
        accept(DEFAULT_PORT);
    }

    /**
     * Releases the bound socket as well as the open client socket if it exists
     * @throws IOException if an I/O error occurs closing sockets
     */
    public void close() throws IOException {
        if (socket != null) {
            super.close();
        }
        serverSocket.close();
    }

    public static void main(String[] args) throws Exception {
        if (debug) {
            System.setProperty("javax.net.debug", NET_DEBUG_MODE);
        }

        SSLConnectionServer server = new SSLConnectionServer(false);
        server.accept(DEFAULT_PORT);
        while (!server.isInboundDone()) {
            byte [] buf = server.recvToken();
            // Empty application messages may be seen more frequently
            // from the BouncyCastle TLS implementation (as part of
            // an IV attack countermeasure).
            if (buf != null && buf.length > 0) {
                System.out.println("Server Recv: " + new String(buf));
                // pong it back
                server.sendToken(buf);
                break; // close connection after the first message
            }
        }
        server.close();
    }
}
