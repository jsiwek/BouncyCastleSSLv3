package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.KeyAgreeRecipientIdentifier;
import org.bouncycastle.asn1.cms.KeyAgreeRecipientInfo;
import org.bouncycastle.asn1.cms.OriginatorIdentifierOrKey;
import org.bouncycastle.asn1.cms.OriginatorPublicKey;
import org.bouncycastle.asn1.cms.RecipientEncryptedKey;
import org.bouncycastle.asn1.cms.RecipientKeyIdentifier;
import org.bouncycastle.asn1.cms.ecc.MQVuserKeyingMaterial;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.spec.MQVPrivateKeySpec;
import org.bouncycastle.jce.spec.MQVPublicKeySpec;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 * the RecipientInfo class for a recipient who has been sent a message
 * encrypted using key agreement.
 */
public class KeyAgreeRecipientInformation
    extends RecipientInformation
{
    private KeyAgreeRecipientInfo info;
    private ASN1OctetString       encryptedKey;

    /**
     * @deprecated
     */
    public KeyAgreeRecipientInformation(
        KeyAgreeRecipientInfo info,
        AlgorithmIdentifier   encAlg,
        InputStream data)
    {
        this(info, encAlg, null, null, data);
    }

    /**
     * @deprecated
     */
    public KeyAgreeRecipientInformation(
        KeyAgreeRecipientInfo info,
        AlgorithmIdentifier   encAlg,
        AlgorithmIdentifier   macAlg,
        InputStream data)
    {
        this(info, encAlg, macAlg, null, data);
    }

    KeyAgreeRecipientInformation(
        KeyAgreeRecipientInfo info,
        AlgorithmIdentifier   encAlg,
        AlgorithmIdentifier   macAlg,
        AlgorithmIdentifier   authEncAlg,
        InputStream data)
    {
        super(encAlg, macAlg, authEncAlg, info.getKeyEncryptionAlgorithm(), data);

        this.info = info;
        this.rid = new RecipientId();

        try
        {
            ASN1Sequence s = this.info.getRecipientEncryptedKeys();

            // TODO Handle the case of more than one encrypted key
            RecipientEncryptedKey id = RecipientEncryptedKey.getInstance(
                    s.getObjectAt(0));

            KeyAgreeRecipientIdentifier karid = id.getIdentifier();

            IssuerAndSerialNumber iAndSN = karid.getIssuerAndSerialNumber();
            if (iAndSN != null)
            {
                rid.setIssuer(iAndSN.getName().getEncoded());
                rid.setSerialNumber(iAndSN.getSerialNumber().getValue());
            }
            else
            {
                RecipientKeyIdentifier rKeyID = karid.getRKeyID();

                // Note: 'date' and 'other' fields of RecipientKeyIdentifier appear to be only informational 

                rid.setSubjectKeyIdentifier(rKeyID.getSubjectKeyIdentifier().getOctets());
            }

            encryptedKey = id.getEncryptedKey();
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("invalid rid in KeyAgreeRecipientInformation");
        }
    }

    private PublicKey getSenderPublicKey(Key receiverPrivateKey,
        OriginatorIdentifierOrKey originator, Provider prov)
        throws CMSException, GeneralSecurityException, IOException
    {
        OriginatorPublicKey opk = originator.getOriginatorKey();
        if (opk != null)
        {
            return getPublicKeyFromOriginatorPublicKey(receiverPrivateKey, opk, prov);
        }

        OriginatorId origID = new OriginatorId();

        IssuerAndSerialNumber iAndSN = originator.getIssuerAndSerialNumber();
        if (iAndSN != null)
        {
            origID.setIssuer(iAndSN.getName().getEncoded());
            origID.setSerialNumber(iAndSN.getSerialNumber().getValue());
        }
        else
        {
            SubjectKeyIdentifier ski = originator.getSubjectKeyIdentifier();

            origID.setSubjectKeyIdentifier(ski.getKeyIdentifier());
        }

        return getPublicKeyFromOriginatorId(origID, prov);
    }

    private PublicKey getPublicKeyFromOriginatorPublicKey(Key receiverPrivateKey,
            OriginatorPublicKey originatorPublicKey, Provider prov)
            throws CMSException, GeneralSecurityException, IOException
    {
        PrivateKeyInfo privInfo = PrivateKeyInfo.getInstance(
            ASN1Object.fromByteArray(receiverPrivateKey.getEncoded()));

        SubjectPublicKeyInfo pubInfo = new SubjectPublicKeyInfo(
            privInfo.getAlgorithmId(),
            originatorPublicKey.getPublicKey().getBytes());
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubInfo.getEncoded());
        KeyFactory fact = KeyFactory.getInstance(keyEncAlg.getObjectId().getId(), prov.getName());
        return fact.generatePublic(pubSpec);
    }

    private PublicKey getPublicKeyFromOriginatorId(OriginatorId origID, Provider prov)
            throws CMSException
    {
        // TODO Support all alternatives for OriginatorIdentifierOrKey
        // see RFC 3852 6.2.2
        throw new CMSException("No support for 'originator' as IssuerAndSerialNumber or SubjectKeyIdentifier");
    }

    private SecretKey calculateAgreedWrapKey(String wrapAlg,
        PublicKey senderPublicKey, PrivateKey receiverPrivateKey, Provider prov)
        throws CMSException, GeneralSecurityException, IOException
    {
        String agreeAlg = keyEncAlg.getObjectId().getId();

        if (agreeAlg.equals(CMSEnvelopedGenerator.ECMQV_SHA1KDF))
        {
            byte[] ukmEncoding = info.getUserKeyingMaterial().getOctets();
            MQVuserKeyingMaterial ukm = MQVuserKeyingMaterial.getInstance(
                ASN1Object.fromByteArray(ukmEncoding));

            PublicKey ephemeralKey = getPublicKeyFromOriginatorPublicKey(receiverPrivateKey,
                ukm.getEphemeralPublicKey(), prov);

            senderPublicKey = new MQVPublicKeySpec(senderPublicKey, ephemeralKey);
            receiverPrivateKey = new MQVPrivateKeySpec(receiverPrivateKey, receiverPrivateKey);
        }

        KeyAgreement agreement = KeyAgreement.getInstance(agreeAlg, prov);
        agreement.init(receiverPrivateKey);
        agreement.doPhase(senderPublicKey, true);
        return agreement.generateSecret(wrapAlg);
    }

    private Key unwrapSessionKey(String wrapAlg, SecretKey agreedKey,
        Provider prov)
        throws GeneralSecurityException
    {
        AlgorithmIdentifier aid = getActiveAlgID();
        String alg = aid.getObjectId().getId();
        byte[] encKeyOctets = encryptedKey.getOctets();

        // TODO Should we try alternate ways of unwrapping?
        //   (see KeyTransRecipientInformation.getSessionKey)
        Cipher keyCipher = Cipher.getInstance(wrapAlg, prov);
        keyCipher.init(Cipher.UNWRAP_MODE, agreedKey);
        return keyCipher.unwrap(encKeyOctets, alg, Cipher.SECRET_KEY);
    }

    protected Key getSessionKey(Key receiverPrivateKey, Provider prov)
        throws CMSException
    {
        try
        {
            String wrapAlg = DERObjectIdentifier.getInstance(
                ASN1Sequence.getInstance(keyEncAlg.getParameters()).getObjectAt(0)).getId();

            PublicKey senderPublicKey = getSenderPublicKey(receiverPrivateKey,
                info.getOriginator(), prov);

            SecretKey agreedWrapKey = calculateAgreedWrapKey(wrapAlg,
                senderPublicKey, (PrivateKey)receiverPrivateKey, prov);

            return unwrapSessionKey(wrapAlg, agreedWrapKey, prov);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new CMSException("can't find algorithm.", e);
        }
        catch (InvalidKeyException e)
        {
            throw new CMSException("key invalid in message.", e);
        }
        catch (InvalidKeySpecException e)
        {
            throw new CMSException("originator key spec invalid.", e);
        }
        catch (NoSuchPaddingException e)
        {
            throw new CMSException("required padding not supported.", e);
        }
        catch (Exception e)
        {
            throw new CMSException("originator key invalid.", e);
        }
    }
    /**
     * decrypt the content and return it
     */
    public CMSTypedStream getContentStream(
        Key key,
        String prov)
        throws CMSException, NoSuchProviderException
    {
        return getContentStream(key, CMSUtils.getProvider(prov));
    }

    public CMSTypedStream getContentStream(
        Key key,
        Provider prov)
        throws CMSException
    {
        Key sKey = getSessionKey(key, prov);

        return getContentFromSessionKey(sKey, prov);
    }
}
