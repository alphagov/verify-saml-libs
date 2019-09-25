package uk.gov.ida.saml.security;

import com.google.common.collect.ImmutableList;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.opensaml.security.credential.Credential;
import uk.gov.ida.saml.core.test.TestCertificateStrings;
import uk.gov.ida.saml.security.saml.OpenSAMLMockitoRunner;
import uk.gov.ida.saml.security.saml.TestCredentialFactory;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(OpenSAMLMockitoRunner.class)
public class SecretKeyDecryptorFactoryTest {

    private Credential credential = new TestCredentialFactory(
            TestCertificateStrings.HUB_TEST_PUBLIC_ENCRYPTION_CERT,
            TestCertificateStrings.HUB_TEST_PRIVATE_ENCRYPTION_KEY)
            .getEncryptionKeyPair();


    @InjectMocks
    private SecretKeyDecryptorFactory factory;

    @Mock
    private IdaKeyStoreCredentialRetriever idaKeyStoreCredentialRetriever;

    @Mock
    private Credential encryptionCredentials;

    @Test
    public void shouldCreateDecreypterUsingPrivateKey() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException {
        SecretKey secretKey = createSecretKey();
        String encryptedSecretKey = encryptSecretKeyWithCredentialsPublicKey(secretKey);
        when(idaKeyStoreCredentialRetriever.getDecryptingCredentials()).thenReturn(ImmutableList.of(encryptionCredentials));
        when(encryptionCredentials.getPrivateKey()).thenReturn(credential.getPrivateKey());
        factory.createDecrypter(encryptedSecretKey);
        verify(idaKeyStoreCredentialRetriever).getDecryptingCredentials();
        verify(encryptionCredentials).getPrivateKey();
    }

    private String encryptSecretKeyWithCredentialsPublicKey(SecretKey secretKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException {
        PublicKey publicKey = credential.getPublicKey();
        Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm());
        cipher.init(Cipher.WRAP_MODE, publicKey);
        return Base64.toBase64String(cipher.wrap(secretKey));
    }

    private SecretKey createSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        keyGenerator.init(56);
        return keyGenerator.generateKey();
    }
}