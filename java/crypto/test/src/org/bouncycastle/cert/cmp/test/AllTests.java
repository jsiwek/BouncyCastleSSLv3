package org.bouncycastle.cert.cmp.test;

import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.CertConfirmContent;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.cmp.CertificateConfirmationContent;
import org.bouncycastle.cert.cmp.CertificateConfirmationContentBuilder;
import org.bouncycastle.cert.cmp.CertificateStatus;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.cert.crmf.PKMACBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcePKMACValuesCalculator;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.io.Streams;

public class AllTests
    extends TestCase
{
    private static final byte[] TEST_DATA = "Hello world!".getBytes();
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final String TEST_DATA_HOME = "bc.test.data.home";

    /*
     *
     *  INFRASTRUCTURE
     *
     */

    public AllTests(String name)
    {
        super(name);
    }

    public static void main(String args[])
    {
        junit.textui.TestRunner.run(AllTests.class);
    }

    public static Test suite()
    {
        return new TestSuite(AllTests.class);
    }

    public void setUp()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public void tearDown()
    {

    }

    public void testProtectedMessage()
        throws Exception
    {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();
        X509CertificateHolder cert = makeV3Certificate(kp, "CN=Test", kp, "CN=Test");

        GeneralName sender = new GeneralName(new X509Name("CN=Sender"));
        GeneralName recipient = new GeneralName(new X509Name("CN=Recip"));

        ContentSigner signer = new JcaContentSignerBuilder("MD5WithRSAEncryption").setProvider(BC).build(kp.getPrivate());
        ProtectedPKIMessage message = new ProtectedPKIMessageBuilder(sender, recipient)
                                                  .setBody(new PKIBody(PKIBody.TYPE_INIT_REP, CertRepMessage.getInstance(new DERSequence(new DERSequence()))))
                                                  .addCMPCertificate(cert)
                                                  .build(signer);

        X509Certificate jcaCert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(message.getCertificates()[0]);
        ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder().setProvider(BC).build(jcaCert.getPublicKey());

        assertTrue(message.verify(verifierProvider));

        assertEquals(sender, message.getHeader().getSender());
        assertEquals(recipient, message.getHeader().getRecipient());
    }

    public void testMacProtectedMessage()
        throws Exception
    {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();
        X509CertificateHolder cert = makeV3Certificate(kp, "CN=Test", kp, "CN=Test");

        GeneralName sender = new GeneralName(new X509Name("CN=Sender"));
        GeneralName recipient = new GeneralName(new X509Name("CN=Recip"));

        ProtectedPKIMessage message = new ProtectedPKIMessageBuilder(sender, recipient)
                                                  .setBody(new PKIBody(PKIBody.TYPE_INIT_REP, CertRepMessage.getInstance(new DERSequence(new DERSequence()))))
                                                  .addCMPCertificate(cert)
                                                  .build(new PKMACBuilder(new JcePKMACValuesCalculator().setProvider(BC)).build("secret".toCharArray()));

        PKMACBuilder pkMacBuilder = new PKMACBuilder(new JcePKMACValuesCalculator().setProvider(BC));

        assertTrue(message.verify(pkMacBuilder, "secret".toCharArray()));

        assertEquals(sender, message.getHeader().getSender());
        assertEquals(recipient, message.getHeader().getRecipient());
    }

    public void testConfirmationMessage()
        throws Exception
    {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();
        X509CertificateHolder cert = makeV3Certificate(kp, "CN=Test", kp, "CN=Test");

        GeneralName sender = new GeneralName(new X509Name("CN=Sender"));
        GeneralName recipient = new GeneralName(new X509Name("CN=Recip"));

        CertificateConfirmationContent content = new CertificateConfirmationContentBuilder()
                             .addAcceptedCertificate(cert, BigInteger.valueOf(1))
                             .build(new JcaDigestCalculatorProviderBuilder().build());

        ContentSigner signer = new JcaContentSignerBuilder("MD5WithRSAEncryption").setProvider(BC).build(kp.getPrivate());
        ProtectedPKIMessage message = new ProtectedPKIMessageBuilder(sender, recipient)
                                                  .setBody(new PKIBody(PKIBody.TYPE_CERT_CONFIRM, content.toASN1Structure()))
                                                  .addCMPCertificate(cert)
                                                  .build(signer);

        X509Certificate jcaCert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(message.getCertificates()[0]);
        ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder().setProvider(BC).build(jcaCert.getPublicKey());

        assertTrue(message.verify(verifierProvider));

        assertEquals(sender, message.getHeader().getSender());
        assertEquals(recipient, message.getHeader().getRecipient());

        content = new CertificateConfirmationContent(CertConfirmContent.getInstance(message.getBody().getContent()));

        CertificateStatus[] statusList = content.getStatusMessages();

        assertEquals(1, statusList.length);
        assertTrue(statusList[0].isVerified(cert, new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()));
    }

    public void testSampleCr()
        throws Exception
    {
        PKIMessage msg = loadMessage("sample_cr.der");
        ProtectedPKIMessage procMsg = new ProtectedPKIMessage(new GeneralPKIMessage(msg));

        assertTrue(procMsg.verify(new PKMACBuilder(new JcePKMACValuesCalculator().setProvider(BC)), "TopSecret1234".toCharArray()));
    }

    private static X509CertificateHolder makeV3Certificate(KeyPair subKP, String _subDN, KeyPair issKP, String _issDN)
        throws GeneralSecurityException, IOException, OperatorCreationException, CertException
    {

        PublicKey subPub  = subKP.getPublic();
        PrivateKey issPriv = issKP.getPrivate();
        PublicKey  issPub  = issKP.getPublic();

        X509v3CertificateBuilder v1CertGen = new JcaX509v3CertificateBuilder(
            new X500Name(_issDN),
            BigInteger.valueOf(System.currentTimeMillis()),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
            new X500Name(_subDN),
            subPub);

        ContentSigner signer = new JcaContentSignerBuilder("SHA1WithRSA").setProvider(BC).build(issPriv);

        X509CertificateHolder certHolder = v1CertGen.build(signer);

        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder().setProvider(BC).build(issPub);

        assertTrue(certHolder.isSignatureValid(verifier));

        return certHolder;
    }

    private static PKIMessage loadMessage(String name)
    {
        String dataHome = System.getProperty(TEST_DATA_HOME);

        if (dataHome == null)
        {
            throw new IllegalStateException(TEST_DATA_HOME + " property not set");
        }

        try
        {
            return PKIMessage.getInstance(ASN1Object.fromByteArray(Streams.readAll(new FileInputStream(dataHome + "/cmp/" + name))));
        }
        catch (IOException e)
        {
            throw new RuntimeException(e.toString());
        }
    }
}