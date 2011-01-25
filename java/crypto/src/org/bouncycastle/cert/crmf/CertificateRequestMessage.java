package org.bouncycastle.cert.crmf;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.Controls;
import org.bouncycastle.asn1.crmf.PKIArchiveOptions;
import org.bouncycastle.asn1.crmf.PKMACValue;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;

public class CertificateRequestMessage
{
    private final CertReqMsg certReqMsg;
    private final Controls controls;

    public CertificateRequestMessage(byte[] certReqMsg)
    {
        this(CertReqMsg.getInstance(certReqMsg));
    }

    public CertificateRequestMessage(CertReqMsg certReqMsg)
    {
        this.certReqMsg = certReqMsg;
        this.controls = certReqMsg.getCertReq().getControls();
    }

    public CertReqMsg toASN1Structure()
    {
        return certReqMsg;
    }

    public CertTemplate getCertTemplate()
    {
        return this.certReqMsg.getCertReq().getCertTemplate();
    }

    public boolean hasControls()
    {
        return controls != null;
    }

    public boolean hasControl(ASN1ObjectIdentifier type)
    {
        return findControl(type) != null;
    }

    public Control getControl(ASN1ObjectIdentifier type)
    {
        AttributeTypeAndValue found = findControl(type);

        if (found != null)
        {
            if (found.getType().equals(CRMFObjectIdentifiers.id_regCtrl_pkiArchiveOptions))
            {
                return new PKIArchiveControl(PKIArchiveOptions.getInstance(found.getValue()));
            }
            if (found.getType().equals(CRMFObjectIdentifiers.id_regCtrl_regToken))
            {
                return new RegTokenControl(DERUTF8String.getInstance(found.getValue()));
            }
            if (found.getType().equals(CRMFObjectIdentifiers.id_regCtrl_authenticator))
            {
                return new AuthenticatorControl(DERUTF8String.getInstance(found.getValue()));
            }
        }

        return null;
    }

    private AttributeTypeAndValue findControl(ASN1ObjectIdentifier type)
    {
        if (controls == null)
        {
            return null;
        }

        AttributeTypeAndValue[] tAndVs = controls.toAttributeTypeAndValueArray();
        AttributeTypeAndValue found = null;

        for (int i = 0; i != tAndVs.length; i++)
        {
            if (tAndVs[i].getType().equals(type))
            {
                found = tAndVs[i];
                break;
            }
        }

        return found;
    }

    public boolean hasProofOfPossession()
    {
        return this.certReqMsg.getPopo() != null;
    }

    public int getProofOfPossessionType()
    {
        return this.certReqMsg.getPopo().getType();
    }

    public boolean hasSigningKeyProofOfPossessionWithPKMAC()
    {
        ProofOfPossession pop = certReqMsg.getPopo();

        if (pop.getType() == ProofOfPossession.TYPE_SIGNING_KEY)
        {
            POPOSigningKey popoSign = POPOSigningKey.getInstance(pop.getObject());

            return popoSign.getPoposkInput().getPublicKeyMAC() != null;
        }

        return false;
    }

    public boolean verifySigningKeyPOP(ContentVerifierProvider verifierProvider)
        throws CRMFException, IllegalStateException
    {
        ProofOfPossession pop = certReqMsg.getPopo();

        if (pop.getType() == ProofOfPossession.TYPE_SIGNING_KEY)
        {
            POPOSigningKey popoSign = POPOSigningKey.getInstance(pop.getObject());

            if (popoSign.getPoposkInput().getPublicKeyMAC() != null)
            {
                throw new IllegalStateException("verification requires password check");
            }

            return verifySignature(verifierProvider, popoSign);
        }
        else
        {
            throw new IllegalStateException("not Signing Key type of proof of possession");
        }
    }

    public boolean verifySigningKeyPOP(ContentVerifierProvider verifierProvider, PKMACBuilder macBuilder, char[] password)
        throws CRMFException, IllegalStateException
    {
        ProofOfPossession pop = certReqMsg.getPopo();

        if (pop.getType() == ProofOfPossession.TYPE_SIGNING_KEY)
        {
            POPOSigningKey popoSign = POPOSigningKey.getInstance(pop.getObject());

            if (popoSign.getPoposkInput().getSender() != null)
            {
                throw new IllegalStateException("no PKMAC present in proof of possession");
            }

            PKMACValue pkMAC = popoSign.getPoposkInput().getPublicKeyMAC();
            PKMACValueVerifier macVerifier = new PKMACValueVerifier(macBuilder);

            if (macVerifier.verify(pkMAC, password, this.getCertTemplate().getPublicKey()))
            {
                return verifySignature(verifierProvider, popoSign);
            }

            return false;
        }
        else
        {
            throw new IllegalStateException("not Signing Key type of proof of possession");
        }
    }

    private boolean verifySignature(ContentVerifierProvider verifierProvider, POPOSigningKey popoSign)
        throws CRMFException
    {
        ContentVerifier verifier;

        try
        {
            verifier = verifierProvider.get(popoSign.getAlgorithmIdentifier());
        }
        catch (OperatorCreationException e)
        {
            throw new CRMFException("unable to create verifier: " + e.getMessage(), e);
        }

        CRMFUtil.derEncodeToStream(popoSign.getPoposkInput(), verifier.getOutputStream());

        return verifier.verify(popoSign.getSignature().getBytes());
    }

    public byte[] getEncoded()
        throws IOException
    {
        return certReqMsg.getEncoded();
    }
}