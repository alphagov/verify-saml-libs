package uk.gov.ida.saml.security;

import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;

public class EncrypterFactory {

    private String dataEncryptionAlgorithm = EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128;

    public EncrypterFactory withAes256Encryption() {
        dataEncryptionAlgorithm = EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256;
        return this;
    }

    public Encrypter createEncrypter(Credential credential) {
        DataEncryptionParameters encParams = new DataEncryptionParameters();
        encParams.setAlgorithm(dataEncryptionAlgorithm);

        KeyEncryptionParameters kekParams = new KeyEncryptionParameters();
        kekParams.setEncryptionCredential(credential);
        kekParams.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);

        Encrypter encrypter = new Encrypter(encParams, kekParams);
        encrypter.setKeyPlacement(Encrypter.KeyPlacement.PEER);

        return encrypter;
    }
}
