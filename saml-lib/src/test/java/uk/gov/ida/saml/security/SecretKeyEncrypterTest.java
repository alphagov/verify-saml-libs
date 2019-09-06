package uk.gov.ida.saml.security;

import org.apache.xml.security.utils.Base64;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.opensaml.security.credential.Credential;
import uk.gov.ida.saml.core.test.TestCertificateStrings;
import uk.gov.ida.saml.security.saml.OpenSAMLMockitoRunner;
import uk.gov.ida.saml.security.saml.TestCredentialFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@RunWith(OpenSAMLMockitoRunner.class)
public class SecretKeyEncrypterTest {
    @Mock
    KeyStoreBackedEncryptionCredentialResolver credentialResolver;

    private SecretKeyEncrypter testSubject;
    private static final String AN_ENTITY_ID = "ministry-of-pies";

    private Credential credential = new TestCredentialFactory(
            TestCertificateStrings.HUB_TEST_PUBLIC_ENCRYPTION_CERT,
            TestCertificateStrings.HUB_TEST_PRIVATE_ENCRYPTION_KEY)
            .getEncryptionKeyPair();

    @Test
    public void shouldSuccessfullyEncryptASecretKey() throws Exception {

        when(credentialResolver.getEncryptingCredential(AN_ENTITY_ID)).thenReturn(credential);

        testSubject = new SecretKeyEncrypter(credentialResolver);

        SecretKey unEncryptedSecretKey = getSecretKey();

        String encryptedSecretKey = testSubject.encryptKeyForEntity(unEncryptedSecretKey, AN_ENTITY_ID);

        Key decryptedSecretKey = decryptSecretKey(encryptedSecretKey);
        assertThat(decryptedSecretKey.getEncoded()).isEqualTo(unEncryptedSecretKey.getEncoded());
    }

    private SecretKey getSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        keyGenerator.init(56);
        return keyGenerator.generateKey();
    }

    private Key decryptSecretKey(String base64EncryptedSecretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.UNWRAP_MODE, credential.getPrivateKey());
        return cipher.unwrap(Base64.decode(base64EncryptedSecretKey), "RSA", Cipher.SECRET_KEY);
    }

}
