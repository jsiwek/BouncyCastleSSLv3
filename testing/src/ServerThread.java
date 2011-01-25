/**
 * A type of thread that runs an SSL server, currently implemented by JSSE's
 * SSLEngine, that listens on a given port
 */
public class ServerThread extends Thread {
    private SSLConnectionServer server;
    private int port;

    /**
     * Constructor
     * @param s an SSL server object
     * @param p the desired port to listen on
     */
    public ServerThread(SSLConnectionServer s, int p) {
        this.server = s;
        this.port = p;
    }

    /**
     * Starts the SSL server listening on the port previous given to
     * constructor.  The first application message sent by the first connection
     * to complete the handshake will be echoed back to the client and the
     * connection closed.
     */
    public void run() {
        try {
            server.accept(port);
            while (!server.isInboundDone()) {
                byte [] buf = server.recvToken();
                // Empty application messages may be seen more frequently
                // from the BouncyCastle TLS implementation (as part of
                // an IV attack countermeasure).
                if (buf != null && buf.length > 0) {
                    // pong it back
                    server.sendToken(buf);
                    break;
                }
            }
            server.close();
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
}
