package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * An implementation of the TLS 1.0 record layer, allowing downgrade to SSLv3.
 */
class RecordStream
{
    private TlsProtocolHandler handler;
    private InputStream is;
    private OutputStream os;
    private byte[] handshake_messages;
    private TlsCipher readCipher = null;
    private TlsCipher writeCipher = null;

    RecordStream(TlsProtocolHandler handler, InputStream is, OutputStream os)
    {
        this.handler = handler;
        this.is = is;
        this.os = os;
        this.handshake_messages = new byte[0];
        this.readCipher = new TlsNullCipher();
        this.writeCipher = this.readCipher;
    }

    void clientCipherSpecDecided(TlsCipher tlsCipher)
    {
        this.writeCipher = tlsCipher;
    }

    void serverClientSpecReceived()
    {
        this.readCipher = this.writeCipher;
    }

    public void readData() throws IOException
    {
        short type = TlsUtils.readUint8(is);
        System.out.println("Read record type: " + type);
        handler.checkVersion(is);
        int size = TlsUtils.readUint16(is);
        System.out.println("Reading record length: " + size);

        byte[] buf = decodeAndVerify(type, is, size);
        handler.processData(type, buf, 0, buf.length);
    }

    protected byte[] decodeAndVerify(short type, InputStream is, int len) throws IOException
    {
        byte[] buf = new byte[len];
        TlsUtils.readFully(buf, is);
        return readCipher.decodeCiphertext(type, buf, 0, buf.length);
    }

    protected void writeMessage(short type, byte[] message, int offset, int len) throws IOException
    {
        if (type == ContentType.handshake)
        {
            updateHandshakeData(message, offset, len);
        }
        byte[] ciphertext = writeCipher.encodePlaintext(type, message, offset, len);
        byte[] writeMessage = new byte[ciphertext.length + 5];
        System.out.println("Write record type: " + type);
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
