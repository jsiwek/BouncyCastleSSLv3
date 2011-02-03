import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.crypto.tls.AlertDescription;
import org.bouncycastle.crypto.tls.AlwaysValidVerifyer;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.CertificateRequest;
import org.bouncycastle.crypto.tls.CertificateVerifyer;
import org.bouncycastle.crypto.tls.CipherSuite;
import org.bouncycastle.crypto.tls.DefaultTlsClient;
import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.TlsCredentials;
import org.bouncycastle.crypto.tls.TlsFatalAlert;
import org.bouncycastle.crypto.tls.TlsProtocolHandler;
import org.bouncycastle.crypto.tls.TlsSignerCredentials;
import org.bouncycastle.util.Arrays;

import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

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

    private static final String KEYSTORE_FILE = "keystore.ImportKey";
    private static final char[] KEYSTORE_PASS = "importkey".toCharArray();
    private static final String KEYSTORE_TYPE = "JKS";

    private static final String[][] protoVariations = {TLSv1, SSLv3, BOTH};
    private static final boolean[] clientAuthVariations = {false, true};

    private void printTestName(String clientImpl, String serverImpl,
                               String[] clientProtos, String[] serverProtos,
                               boolean clientAuth) {
        System.out.println("Testing:\n" +
                           "Client: " + clientImpl + " " +
                           java.util.Arrays.toString(clientProtos) + "\n" +
                           "Server: " + serverImpl + " " +
                           java.util.Arrays.toString(serverProtos) + "\n" +
                           "ClientAuth: " + clientAuth
                           );
    }

    /**
     * JSSE client to JSSE server tests
     * TLSv1, SSLv3 and downgrading TLSv1->SSLv3 are tested with and without
     * client authentication
     * @throws Exception when tests fail to run
     */
    public void testJSSEtoJSSEConnections() throws Exception {
        for (String[] p : protoVariations) {
            for (boolean ca : clientAuthVariations) {
                printTestName("JSSE", "JSSE", p, p, ca);
                SSLConnectionServer server = new SSLConnectionServer(p, ca);
                JSSEServerThread st = new JSSEServerThread(server, JSSE_TEST_PORT);
                st.start();
                Thread.yield();
                JSSEClientConnect(p);
            }
        }

        // Test client downgrade from TLSv1 to SSLv3
        for (boolean ca: clientAuthVariations) {
            printTestName("JSSE", "JSSE", BOTH, SSLv3, ca);
            SSLConnectionServer server = new SSLConnectionServer(SSLv3, ca);
            JSSEServerThread st = new JSSEServerThread(server, JSSE_TEST_PORT);
            st.start();
            Thread.yield();
            JSSEClientConnect(BOTH);
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
     * TODO: test different protocol variations
     * @throws Exception when the tests fail to run
     */
    public void testBCtoJSSEConnections() throws Exception {
        String[][] protoVariations = {BOTH};

        for (String[] p : protoVariations) {
            for (boolean ca : clientAuthVariations) {
                printTestName("BC", "JSSE", p, p, ca);
                SSLConnectionServer server = new SSLConnectionServer(p, ca);
                JSSEServerThread st = new JSSEServerThread(server, BC_TEST_PORT);
                st.start();
                Thread.yield();

                byte[] recv = BCClientConnect(p, BC_TEST_PORT, MSG);

                assertTrue(Arrays.areEqual(MSG, recv));
            }
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
        handler.connect(new TestTlsClient());
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
     * TODO: test different combinations of SSL & TLS versions
     * @throws Exception when the tests fail to run
     */
    public void testBCtoOpenSSLConnections() throws Exception {
        String[][] protoVariations = {BOTH};

        for (String[] p : protoVariations) {
            for (boolean ca : clientAuthVariations) {
                printTestName("BC", "OpenSSL", p, p, ca);
                Process server = startOpenSSLServer(OPENSSL_TEST_PORT, ca, p);

                String msg = "GET /helloworld HTTP/1.1\r\n\r\n";
                try {
                    byte[] recv = BCClientConnect(p, OPENSSL_TEST_PORT,
                                                  msg.getBytes());

                    String recvMsg = new String(recv);
                    assertTrue(recvMsg.contains(new String(MSG)));
                } catch (Exception e) {
                    throw e;
                } finally {
                    server.destroy();
                }
            }
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
        } catch (InterruptedException e) {}

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

    /**
     * implementation of BouncyCastle's TLS credential interface
     * uses same dummy test credentials as the other clients/servers in suite
     */
    class TestTlsCredentials implements TlsSignerCredentials {
        private PrivateKey clientPrivateKey;
        private Certificate clientCert;
        private KeyStore ksKeys;

        public TestTlsCredentials() {
            try {
                ksKeys = KeyStore.getInstance(KEYSTORE_TYPE);
                ksKeys.load(new FileInputStream(KEYSTORE_FILE), KEYSTORE_PASS);
                clientPrivateKey =
                       (PrivateKey) ksKeys.getKey("importkey", KEYSTORE_PASS);
                X509Certificate cert =
                       (X509Certificate) ksKeys.getCertificate("importkey");
                clientCert = new Certificate(
                       new X509CertificateStructure[] {X509CertToStruct(cert)});
            }
            catch (Exception e) {
                e.printStackTrace();
            }
        }

        public byte[] generateCertificateSignature(byte[] md5andsha1)
                throws IOException {
            // encrypt the input hash with the private key to produce signature
            try {
                Cipher cipher = Cipher.getInstance(clientPrivateKey.getAlgorithm());
                cipher.init(Cipher.ENCRYPT_MODE, clientPrivateKey);
                return cipher.doFinal(md5andsha1);
            } catch (Exception e) {
                e.printStackTrace();
                throw new IOException(e);
            }
        }

        public Certificate getCertificate() {
            return clientCert;
        }

        /**
         * TODO: refactor this out somewhere as a utility function
         */
        public X509CertificateStructure X509CertToStruct(X509Certificate c)
                throws CertificateException, IOException {
            ASN1InputStream is = new ASN1InputStream(c.getEncoded());
            DERObject o = is.readObject();
            return X509CertificateStructure.getInstance(o);
        }
    }

    /**
     * Implementation of BouncyCastle's TLS authentication interface
     * All server certificates are accepted
     */
    class TestTlsAuth implements TlsAuthentication {
        protected CertificateVerifyer verifyer;

        public TestTlsAuth(CertificateVerifyer verifyer) {
            this.verifyer = verifyer;
        }

        public void notifyServerCertificate(Certificate serverCertificate)
                throws IOException {
            if (!this.verifyer.isValid(serverCertificate.getCerts()))
            {
                throw new TlsFatalAlert(AlertDescription.user_canceled);
            }
        }

        public TlsCredentials getClientCredentials(CertificateRequest request)
                throws IOException {
            return new TestTlsCredentials();
        }
    }

    /**
     * An implementation of BouncyCastle's TLS client interface
     * The authentication methods are customized for this test suite
     */
    class TestTlsClient extends DefaultTlsClient {
        public TlsAuthentication getAuthentication() throws IOException {
            return new TestTlsAuth(new AlwaysValidVerifyer());
        }

        public int[] getCipherSuites() {
            return new int[] {
                    CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                    CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
            };
        }
    }
}
