package uk.gov.ida.saml.security;

import com.google.common.collect.ImmutableList;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.xmlsec.encryption.EncryptedKey;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import uk.gov.ida.saml.security.exception.SamlFailedToDecryptException;
import uk.gov.ida.saml.security.validators.ValidatedEncryptedAssertionContainer;
import uk.gov.ida.saml.security.validators.encryptedelementtype.EncryptionAlgorithmValidator;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import static uk.gov.ida.saml.security.errors.SamlTransformationErrorFactory.unableToDecrypt;
import static uk.gov.ida.saml.security.errors.SamlTransformationErrorFactory.unableToDecryptXMLEncryptionKey;

public class AssertionDecrypter {

    protected final EncryptionAlgorithmValidator encryptionAlgorithmValidator;
    private Decrypter decrypter;

    public AssertionDecrypter(EncryptionAlgorithmValidator encryptionAlgorithmValidator, Decrypter decrypter) {
        this.encryptionAlgorithmValidator = encryptionAlgorithmValidator;
        this.decrypter = decrypter;
    }

    public List<Assertion> decryptAssertions(ValidatedEncryptedAssertionContainer container) {
        final List<EncryptedAssertion> encryptedAssertions = container.getEncryptedAssertions();
        final ImmutableList.Builder<Assertion> assertions = ImmutableList.builder();

        if (encryptedAssertions.isEmpty()) return assertions.build();

        decrypter.setRootInNewDocument(true);

        for (EncryptedAssertion encryptedAssertion : encryptedAssertions) {
            try {
                encryptionAlgorithmValidator.validate(encryptedAssertion);
                assertions.add(decrypter.decrypt(encryptedAssertion));
            } catch (DecryptionException e) {
                String message = "Problem decrypting assertion " + encryptedAssertion + ".";
                throw new SamlFailedToDecryptException(unableToDecrypt(message), e);
            }
        }

        return assertions.build();
    }

    public List<String> getReEncryptedKeys(ValidatedEncryptedAssertionContainer container,
                                           SecretKeyEncrypter secretKeyEncrypter,
                                           String entityId) {

        final List<String> base64String = new ArrayList<>();
        String algorithm = "";

        for (EncryptedAssertion encryptedAssertion : container.getEncryptedAssertions()) {
            Iterator<EncryptedKey> encryptedKeyIterator = encryptedAssertion.getEncryptedKeys().iterator();
            while (encryptedKeyIterator.hasNext()) {
                try {
                    EncryptedKey encryptedKey = encryptedKeyIterator.next();
                    algorithm = encryptedKey.getEncryptionMethod().getAlgorithm();
                    Key decryptedKey = decrypter.decryptKey(encryptedKey, algorithm);

                    base64String.add(secretKeyEncrypter.encryptKeyForEntity(decryptedKey, entityId));
                } catch (DecryptionException e) {
                    if (!encryptedKeyIterator.hasNext()) {
                        throw new SamlFailedToDecryptException(unableToDecryptXMLEncryptionKey(algorithm), e);
                    }
                }
            }
        }
        return base64String;
    }
}
