import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.crypto.tls.AlwaysValidVerifyer;
import org.bouncycastle.crypto.tls.TlsProtocolHandler;
import org.bouncycastle.util.Arrays;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.LinkedList;
import java.util.List;

/**
 * Tests for different combinations of SSL/TLS client/server configurations
 */
public class BCTlsTest extends TestCase {
    private static final String NET_DEBUG_MODE = "ssl";
    private static final boolean debug = false;
    private static final String[] TLSv1 = {"TLSv1"};
    private static final String[] SSLv3 = {"SSLv3"};
    private static final String[] BOTH = {"TLSv1", "SSLv3"};
    private static final int JSSE_TEST_PORT = 9999;
    private static final int BC_TEST_PORT = 10000;
    private static final int OPENSSL_TEST_PORT = 10001;
    private static final byte[] MSG = "hello world".getBytes();

    /**
     * JSSE client to JSSE server tests
     * TLSv1, SSLv3 and downgrading TLSv1->SSLv3 are tested with and without
     * client authentication
     * @throws Exception when tests fail to run
     */
    public void testJSSEtoJSSEConnections() throws Exception {
        List<String[]> protoVariations = new LinkedList<String[]>();
        protoVariations.add(TLSv1);
        protoVariations.add(SSLv3);
        protoVariations.add(BOTH);

        for (String[] p : protoVariations) {
            for (boolean ca : new boolean[] {true, false}) {
                SSLConnectionServer server = new SSLConnectionServer(p, ca);
                JSSEServerThread st = new JSSEServerThread(server, JSSE_TEST_PORT);
                st.start();
                Thread.yield();
                JSSEClientConnect(p);
            }
        }

        // Test client causing downgrade from TLSv1 to SSLv3
        for (boolean ca: new boolean[] {true, false}) {
            SSLConnectionServer server = new SSLConnectionServer(BOTH, ca);
            JSSEServerThread st = new JSSEServerThread(server, JSSE_TEST_PORT);
            st.start();
            Thread.yield();
            JSSEClientConnect(SSLv3);
        }
    }

    /**
     * Configures the client and attempts to connect to a JSSE server
     * @param protos the SSL/TLS protocol configuration of the client
     * @throws Exception when the connection fails
     */
    private void JSSEClientConnect(String[] protos) throws Exception {
        System.out.println("Client connecting.");
        SSLConnectionClient client = new SSLConnectionClient(protos);

        for (int i = 0; i < 3; ++i) {
            Thread.sleep(1000 * i);
            try {
                client.connect("localhost", JSSE_TEST_PORT);
                break;
            }
            catch (IOException e) {
               if (i == 2) {
                   throw new IOException("Unable to connect");
               }
            }
        }

        client.sendToken(MSG);
        assertTrue(Arrays.areEqual(MSG, client.recvToken()));
        client.close();
    }

    /**
     * BouncyCastle client to JSSE server tests
     * @throws Exception when the tests fail to run
     */
    public void testBCtoJSSEConnections() throws Exception {
        List<String[]> protoVariations = new LinkedList<String[]>();
        protoVariations.add(TLSv1);
        protoVariations.add(SSLv3);
        protoVariations.add(BOTH);

        // TODO: test client authentication
        boolean[] clientAuthVariations = new boolean[] {false};

        for (String[] p : protoVariations) {
            for (boolean ca : clientAuthVariations) {
                SSLConnectionServer server = new SSLConnectionServer(p, ca);
                JSSEServerThread st = new JSSEServerThread(server, BC_TEST_PORT);
                st.start();
                Thread.yield();

                byte[] recv = BCClientConnect(p, BC_TEST_PORT, MSG);

                assertTrue(Arrays.areEqual(MSG, recv));
            }
        }

        // Test downgrade from TLSv1 to SSLv3
        for (boolean ca: clientAuthVariations) {
            SSLConnectionServer server = new SSLConnectionServer(BOTH, ca);
            JSSEServerThread st = new JSSEServerThread(server, BC_TEST_PORT);
            st.start();
            Thread.yield();

            byte[] recv = BCClientConnect(SSLv3, BC_TEST_PORT, MSG);

            assertTrue(Arrays.areEqual(MSG, recv));
        }
    }

    /**
     * Use Bouncy Castle's TLS client implementation to connect to a server
     * @param protos which protocols to use/accept
     * @param port the port to connect to
     * @param sendMsg the message to send to the server
     * @return the message received from the server
     * @throws Exception when the connection fails
     */
    public byte[] BCClientConnect(String[] protos, int port, byte[] sendMsg)
            throws Exception {
        AlwaysValidVerifyer verifier = new AlwaysValidVerifyer();

        Socket s = null;
        for (int i = 0; i < 3; ++i) {
            Thread.sleep(1000 * i);
            try {
                System.out.println("BC client connecting");
                s = new Socket("localhost", port);
                break;
            }
            catch (IOException e) {
            }
        }

        if (s == null) {
            throw new IOException("Unable to connect");
        }

        TlsProtocolHandler handler = new TlsProtocolHandler(
                s.getInputStream(),
                s.getOutputStream());
        handler.setEnabledProtocols(protos);
        handler.connect(verifier);
        InputStream is = handler.getInputStream();
        OutputStream os = handler.getOutputStream();
        os.write(sendMsg);

        byte[] buf = new byte[4096];
        int read = 0;
        int total = 0;

        try {
            while ((read = is.read(buf, total, buf.length - total)) > 0)
            {
                total += read;
            }

            is.close();
        } catch (Exception e) {
            if (total == 0) {
                throw e;
            } else {
                System.err.println("BC client connection closed");
            }
        }
        byte[] tmp = new byte[total];
        System.arraycopy(buf, 0, tmp, 0, total);
        return tmp;
    }

    /**
     * BouncyCastle client to OpenSSL server tests
     * It's expected that a file called "helloworld" exist in the working
     * directory that contains data that the server is will return to
     * connected clients.
     * @throws Exception when the tests fail to run
     */
    public void testBCtoOpenSSLConnections() throws Exception {
        List<String[]> protoVariations = new LinkedList<String[]>();
        protoVariations.add(TLSv1);
        protoVariations.add(SSLv3);
        protoVariations.add(BOTH);

        // TODO: test client authentication
        boolean[] clientAuthVariations = new boolean[] {false};

        for (String[] p : protoVariations) {
            for (boolean ca : clientAuthVariations) {
                Process server = startOpenSSLServer(OPENSSL_TEST_PORT, ca, p);

                String msg = "GET /helloworld HTTP/1.1\r\n\r\n";
                byte[] recv = BCClientConnect(p, OPENSSL_TEST_PORT,
                                              msg.getBytes());

                String recvMsg = new String(recv);
                assertTrue(recvMsg.contains(new String(MSG)));
                server.destroy();
            }
        }

        // Test TLSv1 to SSLv3 connection downgrade
        for (boolean ca : clientAuthVariations) {
            Process server = startOpenSSLServer(OPENSSL_TEST_PORT, ca, BOTH);

            String msg = "GET /helloworld HTTP/1.1\r\n\r\n";
            byte[] recv = BCClientConnect(SSLv3, OPENSSL_TEST_PORT,
                                          msg.getBytes());

            String recvMsg = new String(recv);
            assertTrue(recvMsg.contains(new String(MSG)));
            server.destroy();
        }
    }

    /**
     * Starts an OpenSSL server in web server mode.  It's expected that
     * a server.pem (key pair) exist in the working directory for use with
     * both server and client authentication
     * @param port the port to listen on for incoming connections
     * @param clientAuth whether to authenticate the client
     * @param protos which protocols to accept
     * @return the server process object
     * @throws IOException when failing to start the server
     */
    public Process startOpenSSLServer(int port, boolean clientAuth,
                                      String[] protos)
            throws IOException {
        String command = "openssl s_server -accept " + port + " -WWW"
                       + " -CAfile server.pem";

        if (clientAuth) {
            command += " -Verify 1";
        }

        if (protos == SSLv3) {
            command += " -ssl3";
        } else if (protos == TLSv1) {
            command += " -tls1";
        }

        Process server = Runtime.getRuntime().exec(command);

        // Check whether the server prematurely exited
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) { }

        try {
            int exitVal = server.exitValue();
            System.err.println("OpenSSL server exited with status " + exitVal);
            InputStream err = server.getErrorStream();
            byte[] errBytes = new byte[err.available()];
            err.read(errBytes, 0, errBytes.length);
            System.err.println(new String(errBytes));
        } catch (IllegalThreadStateException e) {
            // This is expected (the server should not have exited yet)
        }

        return server;
    }

    public static TestSuite suite() {
        return new TestSuite(BCTlsTest.class);
    }

    public static void main(String[] args)
            throws Exception {
        if (debug) {
            System.setProperty("javax.net.debug", NET_DEBUG_MODE);
        }

        junit.textui.TestRunner.run(suite());
    }
}
