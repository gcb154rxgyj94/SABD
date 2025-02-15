package org.lab2;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.KeyTransRecipientInformation;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

public class Lab2 {

    private static final String CERTIFICATE_PROVIDER = "BC";
    private static final String SIGN_ALGORITHM = "SHA256withRSA";

    public static void main(String[] args) throws Exception {

        X509Certificate certificate = getCertificate();
        PrivateKey privateKey = getPrivateKey();

        String secretMessage = "My password is 123456Seven";
        System.out.println("Original Message : " + secretMessage);
        byte[] stringToEncrypt = secretMessage.getBytes();
        byte[] encryptedData = encryptData(stringToEncrypt, certificate);
        System.out.println("Encrypted Message : " + new String(encryptedData));
        byte[] rawData = decryptData(encryptedData, privateKey);
        String decryptedMessage = new String(rawData);
        System.out.println("Decrypted Message : " + decryptedMessage);

        byte[] signedData = signData(rawData, certificate, privateKey);
        Boolean check = verifySignedData(signedData);
        System.out.println(check);
    }

    /**
     * Установка нужных пропертей
     */
    private static void setProperty() {
        Security.setProperty("crypto.policy", "unlimited");
    }

    /**
     * Получаем сертификат из файла
     */
    private static X509Certificate getCertificate() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        CertificateFactory certFactory=CertificateFactory.getInstance("X.509", CERTIFICATE_PROVIDER);
        return  (X509Certificate) certFactory.generateCertificate(new FileInputStream("src/main/resources/public.cer"));
    }

    /**
     * Получаем приватный ключ из файла
     */
    private static PrivateKey getPrivateKey() throws Exception {
        char[] keystorePassword = "password".toCharArray();
        char[] keyPassword = "password".toCharArray();
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new FileInputStream("src/main/resources/private.p12"), keystorePassword);
        return  (PrivateKey) keystore.getKey("baeldung", keyPassword);
    }

    /**
     * Шифрование данных с помощью сертификата
     *
     * @param data - данные
     * @param encryptionCertificate - сертификат
     */
    private static byte[] encryptData(byte[] data, X509Certificate encryptionCertificate) throws Exception {
        byte[] encryptedData = null;
        if (data != null && encryptionCertificate != null) {
            CMSEnvelopedDataGenerator cmsEnvelopedDataGenerator = new CMSEnvelopedDataGenerator();
            JceKeyTransRecipientInfoGenerator jceKey = new JceKeyTransRecipientInfoGenerator(encryptionCertificate);
            cmsEnvelopedDataGenerator.addRecipientInfoGenerator(jceKey);
            CMSTypedData msg = new CMSProcessableByteArray(data);
            OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(CERTIFICATE_PROVIDER).build();
            CMSEnvelopedData cmsEnvelopedData = cmsEnvelopedDataGenerator.generate(msg,encryptor);
            encryptedData = cmsEnvelopedData.getEncoded();
        }
        return encryptedData;
    }

    /**
     * Дешифрование данных с помощью секретного ключа
     *
     * @param encryptedData - данные
     * @param decryptionKey - секретный ключ
     */
    public static byte[] decryptData(byte[] encryptedData, PrivateKey decryptionKey) throws Exception {
        if (encryptedData != null && decryptionKey != null) {
            CMSEnvelopedData envelopedData = new CMSEnvelopedData(encryptedData);
            Collection<RecipientInformation> recipients = envelopedData.getRecipientInfos().getRecipients();
            KeyTransRecipientInformation recipientInfo = (KeyTransRecipientInformation) recipients.iterator().next();
            JceKeyTransRecipient recipient = new JceKeyTransEnvelopedRecipient(decryptionKey);
            return recipientInfo.getContent(recipient);
        }
        return null;
    }

    /**
     * Подписать секретное сообщение с помощью цифрового сертификата
     *
     * @param data - секретное сообщение
     * @param signingCertificate - сертификат
     * @param signingKey - ключ
     */
    public static byte[] signData(byte[] data, X509Certificate signingCertificate, PrivateKey signingKey) throws Exception {
        byte[] signedMessage;
        List<X509Certificate> certList = new ArrayList<>();
        CMSTypedData cmsData= new CMSProcessableByteArray(data);
        certList.add(signingCertificate);
        Store certs = new JcaCertStore(certList);
        CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();
        ContentSigner contentSigner = new JcaContentSignerBuilder(SIGN_ALGORITHM).build(signingKey);
        cmsGenerator.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(
                        new JcaDigestCalculatorProviderBuilder().setProvider(CERTIFICATE_PROVIDER).build()
                ).build(contentSigner, signingCertificate)
        );
        cmsGenerator.addCertificates(certs);
        signedMessage = cmsGenerator.generate(cmsData, true).getEncoded();
        return signedMessage;
    }

    /**
     * Верифицируем данные
     *
     * @param signedData - подписанные данные
     */
    public static boolean verifySignedData(byte[] signedData) throws Exception {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(signedData);
        ASN1InputStream asnInputStream = new ASN1InputStream(inputStream);
        CMSSignedData cmsSignedData = new CMSSignedData(ContentInfo.getInstance(asnInputStream.readObject()));
        SignerInformationStore signers = cmsSignedData.getSignerInfos();
        Iterator<SignerInformation> iterator = signers.getSigners().iterator();
        boolean returnValue = true;
        while (iterator.hasNext()) {
            SignerInformation signer = iterator.next();
            Collection<X509CertificateHolder> certCollection = cmsSignedData.getCertificates().getMatches(signer.getSID());
            X509CertificateHolder certHolder = certCollection.iterator().next();
            returnValue = returnValue && signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(certHolder));
        }
        return returnValue;
    }

}
