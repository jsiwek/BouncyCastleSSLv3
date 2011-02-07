package org.bouncycastle.crypto.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * An implementation of the TLS 1.0 record layer, allowing downgrade to SSLv3.
 */
// TODO Use fixed temporary buffers (since there is a limit on the size) for input/output
class RecordStream
{
    private TlsProtocolHandler handler;
    private InputStream is;
    private OutputStream os;
    private byte[] handshake_messages;
    private TlsCompression readCompression = null;
    private TlsCompression writeCompression = null;
    private TlsCipher readCipher = null;
    private TlsCipher writeCipher = null;

    RecordStream(TlsProtocolHandler handler, InputStream is, OutputStream os)
    {
        this.handler = handler;
        this.is = is;
        this.os = os;
        this.handshake_messages = new byte[0];
        this.readCompression = new TlsNullCompression();
        this.writeCompression = this.readCompression;
        this.readCipher = new TlsNullCipher();
        this.writeCipher = this.readCipher;
    }

    void clientCipherSpecDecided(TlsCompression tlsCompression, TlsCipher tlsCipher)
    {
        this.writeCompression = tlsCompression;
        this.writeCipher = tlsCipher;
    }

    void serverClientSpecReceived()
    {
        this.readCompression = this.writeCompression;
        this.readCipher = this.writeCipher;
    }

    public void readData() throws IOException
    {
        int availBytes = is.available();
        if (availBytes < 5) {
            this.handler.incHandshakeBlocking(5 - availBytes);
        }

        short type = TlsUtils.readUint8(is);
        handler.checkVersion(is);
        int size = TlsUtils.readUint16(is);

        availBytes = is.available();
        if (availBytes < size) {
            this.handler.incHandshakeBlocking(size - availBytes);
        }

        byte[] buf = decodeAndVerify(type, is, size);
        handler.processData(type, buf, 0, buf.length);
    }

    protected byte[] decodeAndVerify(short type, InputStream is, int len) throws IOException
    {
        byte[] buf = new byte[len];
        TlsUtils.readFully(buf, is);
        byte[] decoded = readCipher.decodeCiphertext(type, buf, 0, buf.length);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream cOut = readCompression.decompress(bOut);
        cOut.write(decoded, 0, decoded.length);
        cOut.close();
        return bOut.toByteArray();
    }

    protected void writeMessage(short type, byte[] message, int offset, int len) throws IOException
    {
        if (type == ContentType.handshake)
        {
            updateHandshakeData(message, offset, len);
        }

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream cOut = writeCompression.compress(bOut);
        cOut.write(message, offset, len);
        cOut.close();
        byte[] compressed = bOut.toByteArray();

        byte[] ciphertext = writeCipher.encodePlaintext(type, compressed, 0, compressed.length);
        byte[] writeMessage = new byte[ciphertext.length + 5];
        TlsUtils.writeUint8(type, writeMessage, 0);
        handler.writeVersion(writeMessage, 1);
        TlsUtils.writeUint16(ciphertext.length, writeMessage, 3);
        System.arraycopy(ciphertext, 0, writeMessage, 5, ciphertext.length);
        os.write(writeMessage);
        os.flush();
    }

    void updateHandshakeData(byte[] message, int offset, int len)
    {
        byte[] newArr = new byte[handshake_messages.length + len];
        System.arraycopy(handshake_messages, 0, newArr, 0, handshake_messages.length);
        System.arraycopy(message, offset, newArr, handshake_messages.length, len);
        handshake_messages = newArr;
    }

    byte[] getHandshakeMessages() {
        return handshake_messages;
    }

    protected void close() throws IOException
    {
        IOException e = null;
        try
        {
            is.close();
        }
        catch (IOException ex)
        {
            e = ex;
        }
        try
        {
            os.close();
        }
        catch (IOException ex)
        {
            e = ex;
        }
        if (e != null)
        {
            throw e;
        }
    }

    protected void flush() throws IOException
    {
        os.flush();
    }
}
