package org.bouncycastle.cert.cmp;

import java.math.BigInteger;

import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.cmp.RevDetails;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Name;

public class RevocationDetailsBuilder
{
    private CertTemplateBuilder templateBuilder = new CertTemplateBuilder();
    
    public RevocationDetailsBuilder setPublicKey(SubjectPublicKeyInfo publicKey)
    {
        if (publicKey != null)
        {
            templateBuilder.setPublicKey(publicKey);
        }

        return this;
    }

    public RevocationDetailsBuilder setIssuer(X509Name issuer)
    {
        if (issuer != null)
        {
            templateBuilder.setIssuer(issuer);
        }

        return this;
    }

    public RevocationDetailsBuilder setSerialNumber(BigInteger serialNumber)
    {
        if (serialNumber != null)
        {
            templateBuilder.setSerialNumber(new DERInteger(serialNumber));
        }

        return this;
    }

    public RevocationDetailsBuilder setSubject(X509Name subject)
    {
        if (subject != null)
        {
            templateBuilder.setSubject(subject);
        }

        return this;
    }

    public RevocationDetails build()
    {
        return new RevocationDetails(new RevDetails(templateBuilder.build()));
    }
}
