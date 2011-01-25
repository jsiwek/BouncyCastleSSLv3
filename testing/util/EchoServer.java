import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyStore;

/**
 * A typical SSL echo server as implemented by JSSE
 */
public class EchoServer {
    private static final String KEYSTORE_FILE = "testkeys";
    private static final char[] KEYSTORE_PASS = "passphrase".toCharArray();
    private static final String KEYSTORE_TYPE = "JKS";
    private static final String TRUSTMGR_TYPE = "SunX509";

    public static void main(String[] arstring) {
        System.setProperty("javax.net.debug", "all");

        try {
            KeyStore ksKeys = KeyStore.getInstance(KEYSTORE_TYPE);
            ksKeys.load(new FileInputStream(KEYSTORE_FILE), KEYSTORE_PASS);
            KeyStore ksTrust = KeyStore.getInstance(KEYSTORE_TYPE);
            ksTrust.load(new FileInputStream(KEYSTORE_FILE), KEYSTORE_PASS);

            KeyManagerFactory km = KeyManagerFactory.getInstance(TRUSTMGR_TYPE);
            km.init(ksKeys, KEYSTORE_PASS);
            TrustManagerFactory tm = TrustManagerFactory.getInstance(TRUSTMGR_TYPE);
            tm.init(ksTrust);

            SSLContext context = SSLContext.getInstance("TLS");
            context.init(km.getKeyManagers(), tm.getTrustManagers(), null);

            SSLServerSocketFactory sslserversocketfactory =
                    context.getServerSocketFactory();
            SSLServerSocket sslserversocket =
                    (SSLServerSocket) sslserversocketfactory.createServerSocket(9999);
            SSLSocket sslsocket = (SSLSocket) sslserversocket.accept();

            InputStream inputstream = sslsocket.getInputStream();
            InputStreamReader inputstreamreader = new InputStreamReader(inputstream);
            BufferedReader bufferedreader = new BufferedReader(inputstreamreader);

            String string = null;
            while ((string = bufferedreader.readLine()) != null) {
                System.out.println(string);
            }
        } catch (Exception exception) {
            exception.printStackTrace();
        }
    }
}
