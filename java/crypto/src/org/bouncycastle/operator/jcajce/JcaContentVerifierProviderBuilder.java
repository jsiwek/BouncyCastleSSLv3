package org.bouncycastle.operator.jcajce;

import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jcajce.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.NamedJcaJceHelper;
import org.bouncycastle.jcajce.ProviderJcaJceHelper;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DatedContentVerifier;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OperatorStreamException;
import org.bouncycastle.operator.RawContentVerifier;
import org.bouncycastle.operator.RuntimeOperatorException;

public class JcaContentVerifierProviderBuilder
{
    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());

    public JcaContentVerifierProviderBuilder()
    {
    }

    public JcaContentVerifierProviderBuilder setProvider(Provider provider)
    {
        this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

        return this;
    }

    public JcaContentVerifierProviderBuilder setProvider(String providerName)
    {
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

        return this;
    }

    public ContentVerifierProvider build(X509CertificateHolder certHolder)
        throws OperatorCreationException, CertificateException
    {
        return build(helper.convertCertificate(certHolder));
    }

    public ContentVerifierProvider build(final X509Certificate certificate)
        throws OperatorCreationException
    {
        return new ContentVerifierProvider()
        {
            private SignatureOutputStream stream;

            public ContentVerifier get(AlgorithmIdentifier algorithm)
                throws OperatorCreationException
            {
                try
                {
                    Signature sig = helper.createSignature(algorithm);

                    sig.initVerify(certificate.getPublicKey());

                    stream = new SignatureOutputStream(sig);
                }
                catch (GeneralSecurityException e)
                {
                    throw new OperatorCreationException("exception on setup: " + e, e);
                }

                Signature rawSig = createRawSig(algorithm, certificate.getPublicKey());

                if (rawSig != null)
                {
                    return new DatedRawSigVerifier(stream, certificate, rawSig);
                }
                else
                {
                    return new DatedSigVerifier(stream, certificate);
                }
            }
        };
    }

    public ContentVerifierProvider build(final PublicKey publicKey)
        throws OperatorCreationException
    {
        return new ContentVerifierProvider()
        {
            public ContentVerifier get(AlgorithmIdentifier algorithm)
                throws OperatorCreationException
            {
                SignatureOutputStream stream = createSignatureStream(algorithm, publicKey);

                Signature rawSig = createRawSig(algorithm, publicKey);

                if (rawSig != null)
                {
                    return new RawSigVerifier(stream, rawSig);
                }
                else
                {
                    return new SigVerifier(stream);
                }
            }
        };
    }

    private SignatureOutputStream createSignatureStream(AlgorithmIdentifier algorithm, PublicKey publicKey)
        throws OperatorCreationException
    {
        try
        {
            Signature sig = helper.createSignature(algorithm);

            sig.initVerify(publicKey);

            return new SignatureOutputStream(sig);
        }
        catch (GeneralSecurityException e)
        {
            throw new OperatorCreationException("exception on setup: " + e, e);
        }
    }

    private Signature createRawSig(AlgorithmIdentifier algorithm, PublicKey publicKey)
    {
        Signature rawSig;
        try
        {
            rawSig = helper.createRawSignature(algorithm);

            rawSig.initVerify(publicKey);
        }
        catch (Exception e)
        {
            rawSig = null;
        }
        return rawSig;
    }

    private class SigVerifier
        implements ContentVerifier
    {
        private SignatureOutputStream stream;

        SigVerifier(SignatureOutputStream stream)
        {
            this.stream = stream;
        }

        public OutputStream getOutputStream()
        {
            if (stream == null)
            {
                throw new IllegalStateException("verifier not initialised");
            }

            return stream;
        }

        public boolean verify(byte[] expected)
        {
            try
            {
                return stream.verify(expected);
            }
            catch (SignatureException e)
            {
                throw new RuntimeOperatorException("exception obtaining signature: " + e.getMessage(), e);
            }
        }
    }

    private class DatedSigVerifier
        extends SigVerifier
        implements DatedContentVerifier
    {
        private X509Certificate certificate;

        DatedSigVerifier(SignatureOutputStream stream, X509Certificate certificate)
        {
            super(stream);
            this.certificate = certificate;
        }

        public Date getNotBefore()
        {
            return certificate.getNotBefore();
        }

        public Date getNotAfter()
        {
            return certificate.getNotAfter();
        }

        public boolean isValid(Date date)
        {
            return !date.before(getNotBefore()) && !date.after(getNotAfter());
        }
    }

    private class RawSigVerifier
        extends SigVerifier
        implements RawContentVerifier
    {
        private Signature rawSignature;

        RawSigVerifier(SignatureOutputStream stream, Signature rawSignature)
        {
            super(stream);
            this.rawSignature = rawSignature;
        }

        public boolean verify(byte[] digest, byte[] expected)
        {
            try
            {
                rawSignature.update(digest);

                return rawSignature.verify(expected);
            }
            catch (SignatureException e)
            {
                throw new RuntimeOperatorException("exception obtaining raw signature: " + e.getMessage(), e);
            }
        }
    }

    private class DatedRawSigVerifier
        extends RawSigVerifier
        implements DatedContentVerifier
    {
        private X509Certificate certificate;

        DatedRawSigVerifier(SignatureOutputStream stream, X509Certificate certificate, Signature rawSignature)
        {
            super(stream, rawSignature);
            this.certificate = certificate;
        }

        public Date getNotBefore()
        {
            return certificate.getNotBefore();
        }

        public Date getNotAfter()
        {
            return certificate.getNotAfter();
        }

        public boolean isValid(Date date)
        {
            return !date.before(getNotBefore()) && !date.after(getNotAfter());
        }
    }

    private class SignatureOutputStream
        extends OutputStream
    {
        private Signature sig;

        SignatureOutputStream(Signature sig)
        {
            this.sig = sig;
        }

        public void write(byte[] bytes, int off, int len)
            throws IOException
        {
            try
            {
                sig.update(bytes, off, len);
            }
            catch (SignatureException e)
            {
                throw new OperatorStreamException("exception in content signer: " + e.getMessage(), e);
            }
        }

        public void write(byte[] bytes)
            throws IOException
        {
            try
            {
                sig.update(bytes);
            }
            catch (SignatureException e)
            {
                throw new OperatorStreamException("exception in content signer: " + e.getMessage(), e);
            }
        }

        public void write(int b)
            throws IOException
        {
            try
            {
                sig.update((byte)b);
            }
            catch (SignatureException e)
            {
                throw new OperatorStreamException("exception in content signer: " + e.getMessage(), e);
            }
        }

        boolean verify(byte[] expected)
            throws SignatureException
        {
            return sig.verify(expected);
        }
    }
}