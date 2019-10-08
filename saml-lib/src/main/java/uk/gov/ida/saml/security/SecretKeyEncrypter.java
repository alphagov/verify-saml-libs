package uk.gov.ida.saml.security;

import org.bouncycastle.util.encoders.Base64;
import uk.gov.ida.saml.security.exception.SamlFailedToEncryptException;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import static uk.gov.ida.saml.security.errors.SamlTransformationErrorFactory.unableToEncryptXMLEncryptionKey;

public class SecretKeyEncrypter {

    private EncryptionCredentialResolver credentialFactory;

    public SecretKeyEncrypter(EncryptionCredentialResolver credentialFactory) {
        this.credentialFactory = credentialFactory;
    }

    public String encryptKeyForEntity(Key secretKey, String entityId) {
        PublicKey publicKey = credentialFactory.getEncryptingCredential(entityId).getPublicKey();
        try {
            Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm());
            cipher.init(Cipher.WRAP_MODE, publicKey);
            return Base64.toBase64String(cipher.wrap(secretKey));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException e) {
            throw new SamlFailedToEncryptException(unableToEncryptXMLEncryptionKey(), e);
        }
    }
}
