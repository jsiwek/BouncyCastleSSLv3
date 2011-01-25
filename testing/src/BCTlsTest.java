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
    private static final byte[] MSG = "hello world".getBytes();

    /**
     * JSSE client to JSSE server tests
     * TLSv1, SSLv3 and downgrading TLSv1->SSLv3 are tested with and without
     * client authentication
     * @throws Exception
     */
    public void testJSSEtoJSSEConnections() throws Exception {
        List<String[]> protoVariations = new LinkedList<String[]>();
        protoVariations.add(TLSv1);
        protoVariations.add(SSLv3);
        protoVariations.add(BOTH);

        for (String[] p : protoVariations) {
            for (boolean ca : new boolean[] {true, false}) {
                SSLConnectionServer server = new SSLConnectionServer(p, ca);
                ServerThread st = new ServerThread(server, JSSE_TEST_PORT);
                st.start();
                Thread.yield();
                JSSEClientConnect(p);
            }
        }

        // Test client causing downgrade from TLSv1 to SSLv3
        for (boolean ca: new boolean[] {true, false}) {
            SSLConnectionServer server = new SSLConnectionServer(BOTH, ca);
            ServerThread st = new ServerThread(server, JSSE_TEST_PORT);
            st.start();
            Thread.yield();
            JSSEClientConnect(SSLv3);
        }
    }

    /**
     * Configures the client and attempts to connect to a JSSE server
     * @param protos the SSL/TLS protocol configuration of the client
     * @throws Exception
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
     * TODO: test different combinations of SSL & TLS versions and client auth
     * @throws Exception
     */
    public void testBCtoJSSEConnections() throws Exception {
        SSLConnectionServer server = new SSLConnectionServer(BOTH, false);
        ServerThread st = new ServerThread(server, BC_TEST_PORT);
        st.start();
        Thread.yield();

        AlwaysValidVerifyer verifier = new AlwaysValidVerifyer();

        Socket s = null;
        for (int i = 0; i < 3; ++i) {
            Thread.sleep(1000 * i);
            try {
                System.out.println("BC client connecting");
                s = new Socket("localhost", BC_TEST_PORT);
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
        handler.connect(verifier);
        InputStream is = handler.getInputStream();
        OutputStream os = handler.getOutputStream();
        os.write(MSG);

        byte[] buf = new byte[4096];
        int read = 0;
        int total = 0;

        while ((read = is.read(buf, total, buf.length - total)) > 0)
        {
            total += read;
        }

        is.close();
        byte[] tmp = new byte[total];
        System.arraycopy(buf, 0, tmp, 0, total);
        assertTrue(Arrays.areEqual(MSG, tmp));
    }

    //TODO: BouncyCastle client to OpenSSL server tests

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
