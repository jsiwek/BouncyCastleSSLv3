package org.bouncycastle.cms;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CRLException;
import org.bouncycastle.jce.cert.CertStore;
import org.bouncycastle.jce.cert.CertStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BEROctetStringGenerator;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.util.io.Streams;

class CMSUtils
{
    private static final Runtime RUNTIME = Runtime.getRuntime();
    
    static int getMaximumMemory()
    {
        long maxMem = Integer.MAX_VALUE;
        
        if (maxMem > Integer.MAX_VALUE)
        {
            return Integer.MAX_VALUE;
        }
        
        return (int)maxMem;
    }
    
    static ContentInfo readContentInfo(
        byte[] input)
        throws CMSException
    {
        // enforce limit checking as from a byte array
        return readContentInfo(new ASN1InputStream(input));
    }

    static ContentInfo readContentInfo(
        InputStream input)
        throws CMSException
    {
        // enforce some limit checking
        return readContentInfo(new ASN1InputStream(input, getMaximumMemory()));
    } 

    static List getCertificatesFromStore(CertStore certStore)
        throws CertStoreException, CMSException
    {
        List certs = new ArrayList();

        try
        {
            for (Iterator it = certStore.getCertificates(null).iterator(); it.hasNext();)
            {
                X509Certificate c = (X509Certificate)it.next();

                certs.add(X509CertificateStructure.getInstance(
                                                       ASN1Object.fromByteArray(c.getEncoded())));
            }

            return certs;
        }
        catch (IllegalArgumentException e)
        {
            throw new CMSException("error processing certs", e);
        }
        catch (IOException e)
        {
            throw new CMSException("error processing certs", e);
        }
        catch (CertificateEncodingException e)
        {
            throw new CMSException("error encoding certs", e);
        }
    }

    static List getCRLsFromStore(CertStore certStore)
        throws CertStoreException, CMSException
    {
        List crls = new ArrayList();

        try
        {
            for (Iterator it = certStore.getCRLs(null).iterator(); it.hasNext();)
            {
                X509CRL c = (X509CRL)it.next();

                crls.add(CertificateList.getInstance(ASN1Object.fromByteArray(c.getEncoded())));
            }

            return crls;
        }
        catch (IllegalArgumentException e)
        {
            throw new CMSException("error processing crls", e);
        }
        catch (IOException e)
        {
            throw new CMSException("error processing crls", e);
        }
        catch (CRLException e)
        {
            throw new CMSException("error encoding crls", e);
        }
    }

    static ASN1Set createBerSetFromList(List derObjects)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (Iterator it = derObjects.iterator(); it.hasNext();)
        {
            v.add((DEREncodable)it.next());
        }

        return new BERSet(v);
    }

    static ASN1Set createDerSetFromList(List derObjects)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (Iterator it = derObjects.iterator(); it.hasNext();)
        {
            v.add((DEREncodable)it.next());
        }

        return new DERSet(v);
    }

    static OutputStream createBEROctetOutputStream(OutputStream s,
            int tagNo, boolean isExplicit, int bufferSize) throws IOException
    {
        BEROctetStringGenerator octGen = new BEROctetStringGenerator(s, tagNo, isExplicit);

        if (bufferSize != 0)
        {
            return octGen.getOctetOutputStream(new byte[bufferSize]);
        }

        return octGen.getOctetOutputStream();
    }

    static TBSCertificateStructure getTBSCertificateStructure(
        X509Certificate cert) throws CertificateEncodingException
    {
        try
        {
            return TBSCertificateStructure.getInstance(ASN1Object
                .fromByteArray(cert.getTBSCertificate()));
        }
        catch (IOException e)
        {
            throw new CertificateEncodingException(e.toString());
        }
    }

    private static ContentInfo readContentInfo(
        ASN1InputStream in)
        throws CMSException
    {
        try
        {
            return ContentInfo.getInstance(in.readObject());
        }
        catch (IOException e)
        {
            throw new CMSException("IOException reading content.", e);
        }
        catch (ClassCastException e)
        {
            throw new CMSException("Malformed content.", e);
        }
        catch (IllegalArgumentException e)
        {
            throw new CMSException("Malformed content.", e);
        }
    }
    
    public static byte[] streamToByteArray(
        InputStream in) 
        throws IOException
    {
        return Streams.readAll(in);
    }

    public static byte[] streamToByteArray(
        InputStream in,
        int         limit)
        throws IOException
    {
        return Streams.readAllLimited(in, limit);
    }

    public static Provider getProvider(String providerName)
        throws NoSuchProviderException
    {
        if (providerName != null)
        {
            Provider prov = Security.getProvider(providerName);

            if (prov != null)
            {
                return prov;
            }

            throw new NoSuchProviderException("provider " + providerName + " not found.");
        }

        return null; 
    }
}
