import java.io.*;
import java.net.Socket;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;
import java.nio.ByteBuffer;
import java.security.KeyStore;

/**
 * A generic type of SSL/TLS connection that drives handshakes forward using
 * the JSSE SSLEngine class.
 * @author Jon Siwek
 */
public abstract class SSLConnection {
    protected SSLEngine engine;
    protected SSLContext sslContext;
    protected Socket socket;
    private ByteBuffer leftOverNetData;

    protected static final String DEFAULT_HOST = "localhost";
    protected static final int DEFAULT_PORT = 9999;
    protected static final String[] DEFAULT_PROTOCOLS = {"TLSv1", "SSLv3"};

    private static final String KEYSTORE_FILE = "testkeys";
    private static final char[] KEYSTORE_PASS = "passphrase".toCharArray();
    private static final String KEYSTORE_TYPE = "JKS";
    private static final String TRUSTMGR_TYPE = "SunX509";

    private boolean logging = false;
    private boolean showLogHeader = true;

    /**
     * Default constructor simply creates an SSL engine, concrete subclasses
     * are responsible for setting which engine mode and managing the socket
     * @throws Exception on failure to create SSL engine from key/trust material
     */
    public SSLConnection() throws Exception {
        createSSLEngine();
    }

    /**
     * Creates an SSL context and corresponding engine from key/trust material
     * @throws Exception on failure to create SSL engine from key/trust material
     */
    private void createSSLEngine() throws Exception {
        KeyStore ksKeys = KeyStore.getInstance(KEYSTORE_TYPE);
        ksKeys.load(new FileInputStream(KEYSTORE_FILE), KEYSTORE_PASS);
        KeyStore ksTrust = KeyStore.getInstance(KEYSTORE_TYPE);
        ksTrust.load(new FileInputStream(KEYSTORE_FILE), KEYSTORE_PASS);

        KeyManagerFactory km = KeyManagerFactory.getInstance(TRUSTMGR_TYPE);
        km.init(ksKeys, KEYSTORE_PASS);
        TrustManagerFactory tm = TrustManagerFactory.getInstance(TRUSTMGR_TYPE);
        tm.init(ksTrust);

        sslContext = SSLContext.getInstance("TLS");
        sslContext.init(km.getKeyManagers(), tm.getTrustManagers(), null);
        engine = sslContext.createSSLEngine();

        leftOverNetData = ByteBuffer.allocate(
                engine.getSession().getPacketBufferSize());
    }

    /**
     * Logs the result of the given SSLEngineResult
     * @param str a prefix to give to the SSLEngineResult information
     * @param result the SSLEngineResult to log
     */
    protected void log(String str, SSLEngineResult result) {
        if (!logging) {
            return;
        }

        if (showLogHeader) {
            showLogHeader = false;
            System.out.println("The format of the SSLEngineResult is: \n" +
                    "\t\"getStatus() / getHandshakeStatus()\" +\n" +
                    "\t\"bytesConsumed() / bytesProduced()\"\n");
        }

        SSLEngineResult.HandshakeStatus hsStatus = result.getHandshakeStatus();

        log(str +
                result.getStatus() + "/" + hsStatus + ", " +
                result.bytesConsumed() + "/" + result.bytesProduced() +
                " bytes");

        if (hsStatus == SSLEngineResult.HandshakeStatus.FINISHED) {
            log("\t...ready for application data");
        }
    }

    /**
     * Logs a given String to stdout or stderr depending on if it's an error
     * @param str String to display
     * @param isError true if logging should occur on stderr, else false
     */
    protected void log(String str, boolean isError) {
        if (logging) {
            if (isError) {
                System.err.println(str);
            } else {
                System.out.println(str);
            }
        }
    }

    /**
     * Logs a given String to stdout
     * @param str String to display
     */
    protected void log(String str) {
        log(str, false);
    }

    /**
     * Runs delegated tasks as required during handshaking process
     * @throws IllegalStateException when the engine has a NEED_TASK state even
     * after running all current tasks
     */
    protected void runDelegatedTasks() throws IllegalStateException {
        Runnable runnable;

        while ((runnable = engine.getDelegatedTask()) != null) {
            log("\trunning delegated task...");
            runnable.run();
        }

        SSLEngineResult.HandshakeStatus hsStatus = engine.getHandshakeStatus();

        if (hsStatus == SSLEngineResult.HandshakeStatus.NEED_TASK) {
            throw new IllegalStateException(
                    "Unexpected handshake task delegation");
        }

        log("\tnew HandshakeStatus: " + hsStatus);
    }

    /**
     * Sends a data token to the peer.  If an SSLException is emitted from the
     * SSL engine, a close handshake is initiated with the peer before
     * re-throwing the SSLException
     * @param buf the buffer containing data to send. If larger than the maximum
     * application buffer size, it will be split and sent piece-wise
     * @throws IOException when there is a failure to wrap the application data
     * or to write wrapped data to the socket
     */
    public void sendToken(byte[] buf) throws IOException {
        int maxSize = engine.getSession().getApplicationBufferSize();
        int offset = 0;
        int remainder = buf.length;
        ByteBuffer myAppData = ByteBuffer.allocate(maxSize);

        while (remainder > 0) {
            int currentSize = remainder <= maxSize ? remainder : maxSize;
            myAppData.clear();
            myAppData.put(buf, offset, currentSize);
            myAppData.flip();
            sendToken(myAppData);
            offset += currentSize;
            remainder -= currentSize;
        }
    }

    /**
     * Sends a data token to the peer.  If an SSLException is emitted from the
     * SSL engine, a close handshake is initiated with the peer before
     * re-throwing the SSLException
     * @param appData the data to send,
     * @throws IOException when failing to write data to socket
     * @throws SSLException when failing to wrap data
     * @throws IllegalStateException on buffer underflow/overflow
     */
    protected void sendToken(ByteBuffer appData)
            throws IOException, IllegalStateException {
        ByteBuffer netData = ByteBuffer.allocate(
                engine.getSession().getPacketBufferSize());

        boolean isHandshakeToken = isHandshaking();

        SSLEngineResult result;
        try {
            result = engine.wrap(appData, netData);
        } catch(SSLException e) {
            log("unwrap exception: " + e.getMessage());
            close();
            throw e;
        }

        log("wrap: ", result);

        netData.flip();
        OutputStream os = socket.getOutputStream();

        switch (result.getStatus()) {
            case BUFFER_UNDERFLOW:
                // should only happen on unwrap
                throw new IllegalStateException("Unexpected buffer underflow");
            case BUFFER_OVERFLOW:
                // this shouldn't happen because the public sendToken() wrapper
                // is expected to give this method ByteBuffers no larger than
                // the maximum application buffer size
                throw new IllegalStateException("Unexpected buffer overflow");
            case OK:
                // TODO: method that artificially fragments tokens (for testing)
                os.write(netData.array(), 0, netData.limit());
                os.flush();

                if (isHandshakeToken) {
                    // handshake slides to next state
                    return;
                }

                if (isHandshaking()) {
                    // this call to sendToken wasn't initially part of a
                    // handshake, but needs one, so retry afterwards
                    finishHandshake();
                    sendToken(appData);
                } else {
                    // just sent application data
                    log("Sent " + result.bytesConsumed() + " app data bytes");
                }

                break;
            case CLOSED:
                os.write(netData.array(), 0, netData.limit());
                os.flush();
                log("Sent a closing handshake to peer");
                break;
        }
    }

    /**
     * Receives a data token from the peer.  If an SSLException is emitted from
     * the SSL engine, a close handshake is initiated with the peer before
     * re-throwing the SSLException
     * @return a buffer containing the received token or null if the peer
     * sent a close_notify
     * @throws IOException on failure to read data from socket
     * @throws EOFException on socket end-of-stream
     * @throws SSLException on failure to unwrap data
     * @throws IllegalStateException on buffer overflow
     */
    public byte[] recvToken() throws IOException, IllegalStateException {
        SSLSession session = engine.getSession();

        ByteBuffer appData =
                ByteBuffer.allocate(session.getApplicationBufferSize());
        ByteBuffer netData =
                ByteBuffer.allocate(session.getPacketBufferSize());

        SSLEngineResult result;

        boolean isHandshakeToken = isHandshaking();

        do {
            int bytesAvail;

            if (leftOverNetData.position() > 0) {
                // drain any net data leftover from previous receives
                leftOverNetData.flip();
                netData.put(leftOverNetData);
                leftOverNetData.clear();
                bytesAvail = netData.position();
                netData.flip();
            } else {
                // get more data from the socket
                int bytesRead = socket.getInputStream().read(netData.array(),
                        netData.position(),
                        netData.capacity() - netData.position());

                if (bytesRead == -1) {
                    // end of stream; socket closed
                    try {
                        engine.closeInbound();
                    } catch (SSLException e) {
                        //try to flush any remaining close handshake data
                        log(e.getMessage(), true);
                        close();
                    }
                    throw new EOFException("Socket closed");
                }

                // The number of bytes available is the position of the net
                // buffer resulting from the draining of the left-over buffer
                // plus the number of bytes just read from socket.  The net
                // buffer then needs to be prepared to be read by unwrap()
                bytesAvail = netData.position() + bytesRead;
                netData.limit(bytesAvail);
                netData.position(0);
            }

            try {
                result = engine.unwrap(netData, appData);
            } catch (SSLException e) {
                log("unwrap exception: " + e.getMessage());
                close();
                throw e;
            }

            switch (result.getStatus()) {
                case BUFFER_UNDERFLOW:
                    // next iteration fills same net buffer w/ more socket data
                    netData.compact();
                    break;
                case BUFFER_OVERFLOW:
                    // this shouldn't happen because we allocate a destination
                    // buffer based on what the engine's maximum allowed size
                    throw new IllegalStateException(
                            "Unexpected buffer overflow");
                case OK:
                    int bytesConsumed = result.bytesConsumed();

                    if (bytesConsumed < bytesAvail) {
                        netData.compact();
                        netData.flip();
                        leftOverNetData.put(netData);
                    }

                    if (isHandshakeToken) {
                        // handshake slides to next state
                        return null;
                    } else {
                        if (isHandshaking()) {
                            // this call to recvToken wasn't initially part
                            // of a handshake, but needs one, so retry after
                            // handshake finishes
                            finishHandshake();
                            return recvToken();
                        } else {
                            // this call to recvToken wasn't part of a handshake
                            // and does not need to drive a handshake forward
                            // so we have app data to return
                            int bytesProduced = result.bytesProduced();
                            log("Recv " + bytesProduced + " app data bytes");
                            appData.flip();
                            byte[] buf = new byte[appData.limit()];
                            appData.get(buf);
                            return buf;
                        }
                    }
                case CLOSED:
                    // peer is initiating the closure of the SSL/TLS link
                    // send our own closing handshake
                    log("Peer sent a closing handshake");
                    close();
                    break;
            }
        } while (result.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW);

        // should only get here on CLOSED
        return null;
    }

    /**
     * Exchanges tokens with the peer until handshake is complete
     * @throws IOException when handshake fails due to underlying send/recv
     * problems
     */
    protected void finishHandshake() throws IOException {
        while (isHandshaking()) {
            //log("Moving handshake forward", true);
            //checkSecrets();

            switch (engine.getHandshakeStatus()) {
                case NEED_TASK:
                    runDelegatedTasks();
                    break;
                case NEED_WRAP:
                    sendToken(ByteBuffer.allocate(0));
                    break;
                case NEED_UNWRAP:
                    recvToken();
                    break;
            }
        }

        log("Established Common Cipher Suite: " +
                engine.getSession().getCipherSuite());
    }

    /**
     * Checks if this connection is currently handshaking with its peer
     * @return true if in process of handshaking, else false
     */
    public boolean isHandshaking() {
        SSLEngineResult.HandshakeStatus hsStatus = engine.getHandshakeStatus();

        return !(hsStatus == SSLEngineResult.HandshakeStatus.FINISHED ||
                hsStatus == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING);
    }

    /**
     * Checks whether the internal SSL Engine is closed to new outbound messages
     * @return true if the engine has closed the outbound session, else false
     */
    public boolean isOutboundDone() {
        return engine.isOutboundDone();
    }

    /**
     * Checks whether the internal SSL Engine is closed to new inbound messages
     * @return true if the engine's inbound session is closed, else false
     */
    public boolean isInboundDone() {
        return engine.isInboundDone();
    }

    /**
     * Closes the connection with the peer (initiates a handshake with
     * close_notify message).  Is not required to wait for peer's close response
     * (see section 7.2.1 of the TLS specification, RFC 2246).
     *
     * This function will be called internally whenever the SSLEngine emits
     * an SSLException.
     *
     * The inbound side of the connection will be closed automatically by
     * the SSLEngine on unwrapping a close_notify message from a peer.  Also,
     * it will be closed manually on detecting an end-of-stream.
     *
     * @throws IOException when failing to send a close handshake to peer due
     * to underlying send error or when socket closure fails
     */
    public void close() throws IOException {
        engine.closeOutbound();
        while (!engine.isOutboundDone()) {
            sendToken(ByteBuffer.allocate(0));
        }
        socket.close();
    }
}
