package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.params.KeyParameter;

import java.util.Arrays;

/**
 * HMAC implementation based on original internet draft for HMAC (RFC 2104)
 *
 * The difference is that padding is concatentated versus XORed with the key
 *
 * H(K + opad, H(K + ipad, text))
 */
public class SSL3HMac
    implements Mac
{
    private final static byte IPAD = (byte)0x36;
    private final static byte OPAD = (byte)0x5C;

    private static final byte[] MD5_pad1 = genPad(0x36, 48);
    private static final byte[] MD5_pad2 = genPad(0x5c, 48);

    private static final byte[] SHA_pad1 = genPad(0x36, 40);
    private static final byte[] SHA_pad2 = genPad(0x5c, 40);

    private Digest digest;
    private int digestSize;
    private byte[] secret;

    /**
     * Base constructor for one of the standard digest algorithms that the
     * byteLength of the algorithm is know for.
     *
     * @param digest the digest.
     */
    public SSL3HMac(Digest digest)
    {
        this.digest = digest;
        digestSize = digest.getDigestSize();
    }

    public String getAlgorithmName()
    {
        return digest.getAlgorithmName() + "/SSL3HMAC";
    }

    public Digest getUnderlyingDigest()
    {
        return digest;
    }

    public void init(
        CipherParameters params)
    {
        secret = ((KeyParameter)params).getKey();
        init();
    }

    private void init() {
        digest.reset();
        digest.update(secret, 0, secret.length);

        if (digestSize == 16) {
            digest.update(MD5_pad1, 0, MD5_pad1.length);
        } else {
            digest.update(SHA_pad1, 0, SHA_pad1.length);
        }
    }

    public int getMacSize()
    {
        return digestSize;
    }

    public void update(
        byte in)
    {
        digest.update(in);
    }

    public void update(
        byte[] in,
        int inOff,
        int len)
    {
        digest.update(in, inOff, len);
    }

    public int doFinal(
        byte[] out,
        int outOff)
    {
        byte[] tmp = new byte[digestSize];
        digest.doFinal(tmp, 0);

        digest.update(secret, 0, secret.length);
        if (digestSize == 16) {
            digest.update(MD5_pad2, 0, MD5_pad2.length);
        } else {
            digest.update(SHA_pad2, 0, SHA_pad2.length);
        }
        digest.update(tmp, 0, tmp.length);

        int     len = digest.doFinal(out, outOff);

        reset();

        return len;
    }

    /**
     * Reset the mac generator.
     */
    public void reset()
    {
        init();
    }

    private static byte[] genPad(int b, int count) {
        byte[] padding = new byte[count];
        Arrays.fill(padding, (byte) b);
        return padding;
    }
}

