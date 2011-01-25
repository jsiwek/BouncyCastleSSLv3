import org.bouncycastle.crypto.tls.AlwaysValidVerifyer;
import org.bouncycastle.crypto.tls.TlsProtocolHandler;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

/**
 * A simple test of a Bouncy Castle TLS client talking to an echo server
 * (implemented under JSSE)
 */
public class BCTLSConnection {
    public static void main(String[] args) throws Exception {
        ServerThread st = new ServerThread(
                new SSLConnectionServer(false), 9999);
        st.start();
        Thread.yield();

        AlwaysValidVerifyer verifier = new AlwaysValidVerifyer();

        Socket s = new Socket("localhost", 9999);

        TlsProtocolHandler handler = new TlsProtocolHandler(
                s.getInputStream(), s.getOutputStream()
        );

        handler.connect(verifier);

        InputStream is = handler.getInputStream();
        OutputStream os = handler.getOutputStream();

        os.write("hello".getBytes());

        byte[] buf = new byte[4096];
        int read = 0;
        int total = 0;

        try {
            while ((read = is.read(buf, total, buf.length - total)) > 0)
            {
                total += read;
                System.out.println("BC client read " + read);
            }
            System.out.println("BC client total " + total);

            is.close();
        }
        catch (Exception e) {
             e.printStackTrace();
        }

        byte[] tmp = new byte[total];
        System.arraycopy(buf, 0, tmp, 0, total);
        System.out.println("Recv msg: " + new String(tmp));
    }
}
