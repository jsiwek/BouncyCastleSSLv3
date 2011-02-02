package org.bouncycastle.crypto.tls;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.macs.SSL3HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * A generic TLS/SSLv3 MAC implementation, which can be used with any kind of
 * Digest to act as an HMAC.
 */
public class TlsMac
{
    private long seqNo;
    private Mac mac;
    TlsProtocolHandler handler;

    /**
     * Generate a new instance of an TlsMac.
     *
     * @param handler the TLS protocol implementation
     * @param digest The digest to use.
     * @param key_block A byte-array where the key for this mac is located.
     * @param offset The number of bytes to skip, before the key starts in the buffer.
     * @param len The length of the key.
     */
    protected TlsMac(TlsProtocolHandler handler, Digest digest, byte[] key_block, int offset, int len)
    {
        this.handler = handler;
        if (handler.getNegotiatedVersion() == TlsProtocolVersion.SSLv3) {
            this.mac = new SSL3HMac(digest);
        } else {
            this.mac = new HMac(digest);
        }
        KeyParameter param = new KeyParameter(key_block, offset, len);
        this.mac.init(param);
        this.seqNo = 0;
    }

    /**
     * @return The Keysize of the mac.
     */
    protected int getSize()
    {
        return mac.getMacSize();
    }

    /**
     * Calculate the mac for some given data.
     * <p/>
     * TlsMac will keep track of the sequence number internally.
     * 
     * @param type The message type of the message.
     * @param message A byte-buffer containing the message.
     * @param offset The number of bytes to skip, before the message starts.
     * @param len The length of the message.
     * @return A new byte-buffer containing the mac value.
     */
    protected byte[] calculateMac(short type, byte[] message, int offset, int len)
    {
        ByteArrayOutputStream bosMac;
        if (handler.getNegotiatedVersion() == TlsProtocolVersion.SSLv3) {
            // SSLv3 does not include the protocol version
            bosMac = new ByteArrayOutputStream(11);
        } else {
            bosMac = new ByteArrayOutputStream(13);
        }
        try
        {
            TlsUtils.writeUint64(seqNo++, bosMac);
            TlsUtils.writeUint8(type, bosMac);
            if (handler.getNegotiatedVersion() != TlsProtocolVersion.SSLv3) {
                handler.writeVersion(bosMac);
            }
            TlsUtils.writeUint16(len, bosMac);
        }
        catch (IOException e)
        {
            // This should never happen
            throw new IllegalStateException("Internal error during mac calculation");
        }

        byte[] macHeader = bosMac.toByteArray();
        mac.update(macHeader, 0, macHeader.length);
        mac.update(message, offset, len);

        byte[] result = new byte[mac.getMacSize()];
        mac.doFinal(result, 0);
        return result;
    }

}
