package org.bouncycastle.jce.provider;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.SignedData;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.X509CertificateStructure;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactorySpi;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

/**
 * class for dealing with X509 certificates.
 * <p>
 * At the moment this will deal with "-----BEGIN CERTIFICATE-----" to "-----END CERTIFICATE-----"
 * base 64 encoded certs, as well as the BER binaries of certificates and some classes of PKCS#7
 * objects.
 */
public class JDKX509CertificateFactory
    extends CertificateFactorySpi
{
    private static final PEMUtil PEM_CERT_PARSER = new PEMUtil("CERTIFICATE");
    private static final PEMUtil PEM_CRL_PARSER = new PEMUtil("CRL");

    private SignedData         sData = null;
    private int                sDataObjectCount = 0;
    private InputStream        currentStream = null;
    
    private SignedData         sCrlData = null;
    private int                sCrlDataObjectCount = 0;
    private InputStream        currentCrlStream = null;

    private Certificate readDERCertificate(
        ASN1InputStream dIn)
        throws IOException
    {
        ASN1Sequence    seq = (ASN1Sequence)dIn.readObject();

        if (seq.size() > 1
                && seq.getObjectAt(0) instanceof DERObjectIdentifier)
        {
            if (seq.getObjectAt(0).equals(PKCSObjectIdentifiers.signedData))
            {
                sData = new SignedData(ASN1Sequence.getInstance(
                                (ASN1TaggedObject)seq.getObjectAt(1), true));

                return getCertificate();
            }
        }

        return new X509CertificateObject(
                            X509CertificateStructure.getInstance(seq));
    }

    private Certificate getCertificate()
    {
        while (sDataObjectCount < sData.getCertificates().size())
        {
            Object obj = sData.getCertificates().getObjectAt(sDataObjectCount++);

            if (obj instanceof ASN1Sequence)
            {
               return new X509CertificateObject(
                                X509CertificateStructure.getInstance(obj));
            }
        }

        return null;
    }

    private Certificate readPEMCertificate(
        InputStream  in)
        throws IOException
    {
        ASN1Sequence seq = PEM_CERT_PARSER.readPEMObject(in);

        if (seq != null)
        {
            return new X509CertificateObject(
                            X509CertificateStructure.getInstance(seq));
        }

        return null;
    }

    private CRL readPEMCRL(
        InputStream  in)
        throws IOException, CRLException
    {
        ASN1Sequence seq = PEM_CRL_PARSER.readPEMObject(in);

        if (seq != null)
        {
            return new X509CRLObject(
                            CertificateList.getInstance(seq));
        }

        return null;
    }

    private CRL readDERCRL(
        InputStream  in)
        throws IOException, CRLException
    {
        ASN1InputStream  dIn = new ASN1InputStream(in, ProviderUtil.getReadLimit(in));
        ASN1Sequence     seq = (ASN1Sequence)dIn.readObject();

        if (seq.size() > 1
                && seq.getObjectAt(0) instanceof DERObjectIdentifier)
        {
            if (seq.getObjectAt(0).equals(PKCSObjectIdentifiers.signedData))
            {
                sCrlData = new SignedData(ASN1Sequence.getInstance(
                                (ASN1TaggedObject)seq.getObjectAt(1), true));
    
                return getCRL();
            }
        }

        return new X509CRLObject(
                     CertificateList.getInstance(seq));
    }

    private CRL getCRL()
        throws CRLException
    {
        if (sCrlDataObjectCount >= sCrlData.getCRLs().size())
        {
            return null;
        }

        return new X509CRLObject(
                            CertificateList.getInstance(
                                    sCrlData.getCRLs().getObjectAt(sCrlDataObjectCount++)));
    }

    /**
     * Generates a certificate object and initializes it with the data
     * read from the input stream inStream.
     */
    public Certificate engineGenerateCertificate(
        InputStream in) 
        throws CertificateException
    {
        if (currentStream == null)
        {
            currentStream = in;
            sData = null;
            sDataObjectCount = 0;
        }
        else if (currentStream != in) // reset if input stream has changed
        {
            currentStream = in;
            sData = null;
            sDataObjectCount = 0;
        }

        try
        {
            if (sData != null)
            {
                if (sDataObjectCount != sData.getCertificates().size())
                {
                    return getCertificate();
                }
                else
                {
                    sData = null;
                    sDataObjectCount = 0;
                    return null;
                }
            }
            
            if (!in.markSupported())
            {
                in = new BufferedInputStream(in);
            }
            
            in.mark(10);
            int    tag = in.read();
            
            if (tag == -1)
            {
                return null;
            }
            
            if (tag != 0x30)  // assume ascii PEM encoded.
            {
                in.reset();
                return readPEMCertificate(in);
            }
            else
            {
                in.reset();
                return readDERCertificate(new ASN1InputStream(in, ProviderUtil.getReadLimit(in)));
            }
        }
        catch (Exception e)
        {
            throw new CertificateException(e.toString());
        }
    }

    /**
     * Returns a (possibly empty) collection view of the certificates
     * read from the given input stream inStream.
     */
    public Collection engineGenerateCertificates(
        InputStream inStream) 
        throws CertificateException
    {
        Certificate     cert;
        List            certs = new ArrayList();

        while ((cert = engineGenerateCertificate(inStream)) != null)
        {
            certs.add(cert);
        }

        return certs;
    }

    /**
     * Generates a certificate revocation list (CRL) object and initializes
     * it with the data read from the input stream inStream.
     */
    public CRL engineGenerateCRL(
        InputStream inStream) 
        throws CRLException
    {
        if (currentCrlStream == null)
        {
            currentCrlStream = inStream;
            sCrlData = null;
            sCrlDataObjectCount = 0;
        }
        else if (currentCrlStream != inStream) // reset if input stream has changed
        {
            currentCrlStream = inStream;
            sCrlData = null;
            sCrlDataObjectCount = 0;
        }

        try
        {
            if (sCrlData != null)
            {
                if (sCrlDataObjectCount != sCrlData.getCRLs().size())
                {
                    return getCRL();
                }
                else
                {
                    sCrlData = null;
                    sCrlDataObjectCount = 0;
                    return null;
                }
            }
            
            if (!inStream.markSupported())
            {
                inStream = new BufferedInputStream(inStream);
            }
            
            inStream.mark(10);
            if (inStream.read() != 0x30)  // assume ascii PEM encoded.
            {
                inStream.reset();
                return readPEMCRL(inStream);
            }
            else
            {
                inStream.reset();
                return readDERCRL(new ASN1InputStream(inStream, ProviderUtil.getReadLimit(inStream)));
            }
        }
        catch (CRLException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new CRLException(e.toString());
        }
    }

    /**
     * Returns a (possibly empty) collection view of the CRLs read from
     * the given input stream inStream.
     *
     * The inStream may contain a sequence of DER-encoded CRLs, or
     * a PKCS#7 CRL set.  This is a PKCS#7 SignedData object, with the
     * only signficant field being crls.  In particular the signature
     * and the contents are ignored.
     */
    public Collection engineGenerateCRLs(
        InputStream inStream) 
        throws CRLException
    {
        CRL     crl;
        List    crls = new ArrayList();

        while ((crl = engineGenerateCRL(inStream)) != null)
        {
            crls.add(crl);
        }

        return crls;
    }

    public Iterator engineGetCertPathEncodings()
    {
        return PKIXCertPath.certPathEncodings.iterator();
    }

    public CertPath engineGenerateCertPath(
        InputStream inStream)
        throws CertificateException
    {
        return engineGenerateCertPath(inStream, "PkiPath");
    }

    public CertPath engineGenerateCertPath(
        InputStream inStream,
        String encoding)
        throws CertificateException
    {
        return new PKIXCertPath(inStream, encoding);
    }

    public CertPath engineGenerateCertPath(
        List certificates)
        throws CertificateException
    {
        Iterator iter = certificates.iterator();
        Object obj;
        while (iter.hasNext())
        {
            obj = iter.next();
            if (obj != null)
            {
                if (!(obj instanceof X509Certificate))
                {
                    throw new CertificateException("list contains none X509Certificate object while creating CertPath\n" + obj.toString());
                }
            }
        }
        return new PKIXCertPath(certificates);
    }
}
