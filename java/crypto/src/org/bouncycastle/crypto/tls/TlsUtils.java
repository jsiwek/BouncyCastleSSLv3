package org.bouncycastle.crypto.tls;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;

/**
 * Some helper fuctions for MicroTLS.
 */
public class TlsUtils
{
    protected static void writeUint8(short i, OutputStream os) throws IOException
    {
        os.write(i);
    }

    protected static void writeUint8(short i, byte[] buf, int offset)
    {
        buf[offset] = (byte)i;
    }

    protected static void writeUint16(int i, OutputStream os) throws IOException
    {
        os.write(i >> 8);
        os.write(i);
    }

    protected static void writeUint16(int i, byte[] buf, int offset)
    {
        buf[offset] = (byte)(i >> 8);
        buf[offset + 1] = (byte)i;
    }

    protected static void writeUint24(int i, OutputStream os) throws IOException
    {
        os.write(i >> 16);
        os.write(i >> 8);
        os.write(i);
    }

    protected static void writeUint24(int i, byte[] buf, int offset)
    {
        buf[offset] = (byte)(i >> 16);
        buf[offset + 1] = (byte)(i >> 8);
        buf[offset + 2] = (byte)(i);
    }

    protected static void writeUint32(long i, OutputStream os) throws IOException
    {
        os.write((int)(i >> 24));
        os.write((int)(i >> 16));
        os.write((int)(i >> 8));
        os.write((int)(i));
    }

    protected static void writeUint32(long i, byte[] buf, int offset)
    {
        buf[offset] = (byte)(i >> 24);
        buf[offset + 1] = (byte)(i >> 16);
        buf[offset + 2] = (byte)(i >> 8);
        buf[offset + 3] = (byte)(i);
    }

    protected static void writeUint64(long i, OutputStream os) throws IOException
    {
        os.write((int)(i >> 56));
        os.write((int)(i >> 48));
        os.write((int)(i >> 40));
        os.write((int)(i >> 32));
        os.write((int)(i >> 24));
        os.write((int)(i >> 16));
        os.write((int)(i >> 8));
        os.write((int)(i));
    }


    protected static void writeUint64(long i, byte[] buf, int offset)
    {
        buf[offset] = (byte)(i >> 56);
        buf[offset + 1] = (byte)(i >> 48);
        buf[offset + 2] = (byte)(i >> 40);
        buf[offset + 3] = (byte)(i >> 32);
        buf[offset + 4] = (byte)(i >> 24);
        buf[offset + 5] = (byte)(i >> 16);
        buf[offset + 6] = (byte)(i >> 8);
        buf[offset + 7] = (byte)(i);
    }

    protected static void writeOpaque8(byte[] buf, OutputStream os) throws IOException
    {
        writeUint8((short)buf.length, os);
        os.write(buf);
    }

    protected static void writeOpaque16(byte[] buf, OutputStream os) throws IOException
    {
        writeUint16(buf.length, os);
        os.write(buf);
    }

    protected static void writeOpaque24(byte[] buf, OutputStream os) throws IOException
    {
        writeUint24(buf.length, os);
        os.write(buf);
    }

    protected static void writeUint8Array(short[] uints, OutputStream os) throws IOException
    {
        for (int i = 0; i < uints.length; ++i)
        {
            writeUint8(uints[i], os);
        }
    }

    protected static void writeUint16Array(int[] uints, OutputStream os) throws IOException
    {
        for (int i = 0; i < uints.length; ++i)
        {
            writeUint16(uints[i], os);
        }
    }

    protected static short readUint8(InputStream is) throws IOException
    {
        int i = is.read();
        if (i == -1)
        {
            throw new EOFException();
        }
        return (short)i;
    }

    protected static int readUint16(InputStream is) throws IOException
    {
        int i1 = is.read();
        int i2 = is.read();
        if ((i1 | i2) < 0)
        {
            throw new EOFException();
        }
        return i1 << 8 | i2;
    }

    protected static int readUint24(InputStream is) throws IOException
    {
        int i1 = is.read();
        int i2 = is.read();
        int i3 = is.read();
        if ((i1 | i2 | i3) < 0)
        {
            throw new EOFException();
        }
        return (i1 << 16) | (i2 << 8) | i3;
    }

    protected static long readUint32(InputStream is) throws IOException
    {
        int i1 = is.read();
        int i2 = is.read();
        int i3 = is.read();
        int i4 = is.read();
        if ((i1 | i2 | i3 | i4) < 0)
        {
            throw new EOFException();
        }
        return (((long)i1) << 24) | (((long)i2) << 16) | (((long)i3) << 8) | ((long)i4);
    }

    protected static void readFully(byte[] buf, InputStream is) throws IOException
    {
        if (Streams.readFully(is, buf) != buf.length)
        {
            throw new EOFException();
        }
    }

    protected static byte[] readOpaque8(InputStream is) throws IOException
    {
        short length = readUint8(is);
        byte[] value = new byte[length];
        readFully(value, is);
        return value;
    }

    protected static byte[] readOpaque16(InputStream is) throws IOException
    {
        int length = readUint16(is);
        byte[] value = new byte[length];
        readFully(value, is);
        return value;
    }

    protected static void writeGMTUnixTime(byte[] buf, int offset)
    {
        int t = (int)(System.currentTimeMillis() / 1000L);
        buf[offset] = (byte)(t >> 24);
        buf[offset + 1] = (byte)(t >> 16);
        buf[offset + 2] = (byte)(t >> 8);
        buf[offset + 3] = (byte)t;
    }

    private static void hmac_hash(Digest digest, byte[] secret, byte[] seed, byte[] out)
    {
        HMac mac = new HMac(digest);
        KeyParameter param = new KeyParameter(secret);
        byte[] a = seed;
        int size = digest.getDigestSize();
        int iterations = (out.length + size - 1) / size;
        byte[] buf = new byte[mac.getMacSize()];
        byte[] buf2 = new byte[mac.getMacSize()];
        for (int i = 0; i < iterations; i++)
        {
            mac.init(param);
            mac.update(a, 0, a.length);
            mac.doFinal(buf, 0);
            a = buf;
            mac.init(param);
            mac.update(a, 0, a.length);
            mac.update(seed, 0, seed.length);
            mac.doFinal(buf2, 0);
            System.arraycopy(buf2, 0, out, (size * i), Math.min(size, out.length - (size * i)));
        }
    }

    protected static byte[] PRF(byte[] secret, String asciiLabel, byte[] seed, int size)
    {
        byte[] label = Strings.toByteArray(asciiLabel);

        int s_half = (secret.length + 1) / 2;
        byte[] s1 = new byte[s_half];
        byte[] s2 = new byte[s_half];
        System.arraycopy(secret, 0, s1, 0, s_half);
        System.arraycopy(secret, secret.length - s_half, s2, 0, s_half);

        byte[] ls = concat(label, seed);

        byte[] buf = new byte[size];
        byte[] prf = new byte[size];
        hmac_hash(new MD5Digest(), s1, ls, prf);
        hmac_hash(new SHA1Digest(), s2, ls, buf);
        for (int i = 0; i < size; i++)
        {
            buf[i] ^= prf[i];
        }
        return buf;
    }

    static byte[] concat(byte[] a, byte[] b)
    {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

    // TODO: clean up and refactor SSLv3 versus TLsv1 utility functions below

    protected static void updateDigest(MessageDigest md, byte[] hs_msgs,
                      byte[] sender, byte[] secret, byte[] pad1, byte[] pad2) {
        md.update(hs_msgs);
        if (sender != null) md.update(sender);
        md.update(secret);
        md.update(pad1);

        byte[] tmp = md.digest();

        md.update(secret);
        md.update(pad2);
        md.update(tmp);
    }

    // byte[] sender only sent for finish message
    protected static byte[] getSSLHandshakeHash(byte[] sender, byte[] secret,
                                                byte[] handshake_messages)
            throws DigestException, NoSuchAlgorithmException {
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");

        updateDigest(md5, handshake_messages, sender, secret, MD5_pad1, MD5_pad2);
        updateDigest(sha1, handshake_messages, sender, secret, SHA_pad1, SHA_pad2);

        byte[] rval = new byte[36];

        md5.digest(rval, 0, 16);
        sha1.digest(rval, 16, 20);
        return rval;
    }

    protected static byte[] getCertVerify(boolean sslv3, byte[] secret,
                                          byte[] handshake_messages)
            throws IOException {
        if (sslv3) {
            try {
                return getSSLHandshakeHash(null, secret, handshake_messages);
            } catch (Exception e) {
                e.printStackTrace();
                throw new IOException(e);
            }
        } else {
            CombinedHash hash = new CombinedHash();
            hash.update(handshake_messages, 0, handshake_messages.length);
            byte[] bs = new byte[hash.getDigestSize()];
            hash.doFinal(bs, 0);
            return bs;
        }
    }

    protected static byte[] getFinishedMsg(boolean sslv3, byte[] secret,
                                        byte[] handshake_messages, String msg,
                                        byte[] sender)
            throws IOException {
        byte[] verifyData;
        if (sslv3) {
            try {
                verifyData = getSSLHandshakeHash(sender,
                        secret, handshake_messages);
            } catch (Exception e) {
                e.printStackTrace();
                throw new IOException(e);
            }
        } else {
            CombinedHash hash = new CombinedHash();
            hash.update(handshake_messages, 0, handshake_messages.length);
            byte[] bs = new byte[hash.getDigestSize()];
            hash.doFinal(bs, 0);

            verifyData = PRF(secret, msg, bs, 12);
        }

        return verifyData;
    }

    protected static byte[] calculateMasterSecret(boolean sslv3,
                                                  byte[] pre_master_secret,
                                                  byte[] client_random,
                                                  byte[] server_random)
            throws IOException {
        if (sslv3) {
            try {
                MessageDigest md5 = MessageDigest.getInstance("MD5");
                MessageDigest sha1 = MessageDigest.getInstance("SHA-1");

                byte rval[] = new byte[0];

                for (int i = 0; i < 3; ++i) {
                    rval = concat(rval,
                        md5.digest(concat(pre_master_secret,
                        sha1.digest(concat(SSL3_CONST[i],
                                    concat(pre_master_secret,
                                    concat(client_random, server_random)))))));
                }

                return rval;
            } catch (Exception e) {
                throw new IOException(e);
            }
        } else {
            return PRF(pre_master_secret, "master secret",
                    concat(client_random, server_random), 48);
        }
    }

    protected static byte[] calculateKeyBlock(boolean sslv3, int prfSize,
                                               byte[] master_secret,
                                               byte[] client_random,
                                               byte[] server_random) {
        if (sslv3) {
            try {
                int i = 0;
                byte tmp[] = new byte[0];

                MessageDigest md5 = MessageDigest.getInstance("MD5");
                MessageDigest sha1 = MessageDigest.getInstance("SHA-1");

                while (tmp.length < prfSize) {
                    tmp = concat(tmp,
                        md5.digest(concat(master_secret,
                        sha1.digest(concat(SSL3_CONST[i],
                                    concat(master_secret,
                                    concat(server_random, client_random)))))));
                    ++i;
                }

                byte rval[] = new byte[prfSize];
                System.arraycopy(tmp, 0, rval, 0, prfSize);
                return rval;
            } catch (Exception e) {
                e.printStackTrace();
                return null; //TODO: yuck
            }
        } else {
            return PRF(master_secret, "key expansion",
                    concat(server_random, client_random), prfSize);
        }
    }

    static final byte[] MD5_pad1 = genPad(0x36, 48);
    static final byte[] MD5_pad2 = genPad(0x5c, 48);

    static final byte[] SHA_pad1 = genPad(0x36, 40);
    static final byte[] SHA_pad2 = genPad(0x5c, 40);

    private static byte[] genPad(int b, int count) {
        byte[] padding = new byte[count];
        Arrays.fill(padding, (byte) b);
        return padding;
    }

    static final byte[] SSL_CLIENT = { 0x43, 0x4C, 0x4E, 0x54 };
    static final byte[] SSL_SERVER = { 0x53, 0x52, 0x56, 0x52 };

    // SSL3 magic mix constants ("A", "BB", "CCC", ...)
    final static byte[][] SSL3_CONST = genConst();

    private static byte[][] genConst() {
        int n = 10;
        byte[][] arr = new byte[n][];
        for (int i = 0; i < n; i++) {
            byte[] b = new byte[i + 1];
            Arrays.fill(b, (byte)('A' + i));
            arr[i] = b;
        }
        return arr;
    }
}
