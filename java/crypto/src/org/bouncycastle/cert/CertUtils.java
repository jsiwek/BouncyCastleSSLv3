package org.bouncycastle.cert;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.operator.ContentSigner;

class CertUtils
{
    static X509CertificateHolder generateFullCert(ContentSigner signer, TBSCertificateStructure tbsCert)
    {
        try
        {
            OutputStream sOut = signer.getOutputStream();

            sOut.write(tbsCert.getDEREncoded());

            sOut.close();

            return new X509CertificateHolder(generateStructure(tbsCert, signer.getAlgorithmIdentifier(), signer.getSignature()));
        }
        catch (IOException e)
        {
            throw new IllegalStateException("cannot produce certificate signature");
        }
    }

    private static X509CertificateStructure generateStructure(TBSCertificateStructure tbsCert, AlgorithmIdentifier sigAlgId, byte[] signature)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(tbsCert);
        v.add(sigAlgId);
        v.add(new DERBitString(signature));

        return X509CertificateStructure.getInstance(new DERSequence(v));
    }
}
