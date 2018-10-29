package uk.gov.ida.saml.security;

import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.RSAOAEPParameters;

public class EncrypterFactory {
    private String keyEncryptionAlgorithm = EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP;
    private String dataEncryptionAlgorithm = EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128;
    private Encrypter.KeyPlacement keyPlacement = Encrypter.KeyPlacement.PEER;
    private boolean useSha256Digest = false;

    public EncrypterFactory withKeyEncryptionAlgorithm(String algorithm) {
        keyEncryptionAlgorithm = algorithm;
        return this;
    }

    public EncrypterFactory withDataEncryptionAlgorithm(String algorithm) {
        dataEncryptionAlgorithm = algorithm;
        return this;
    }

    public EncrypterFactory withKeyPlacement(Encrypter.KeyPlacement keyPlacement) {
        this.keyPlacement = keyPlacement;
        return this;
    }

    public EncrypterFactory withSha256KeySignatureDigest() {
        useSha256Digest = true;
        return this;
    }

    public Encrypter createEncrypter(Credential credential) {
        DataEncryptionParameters encParams = new DataEncryptionParameters();
        encParams.setAlgorithm(dataEncryptionAlgorithm);

        KeyEncryptionParameters kekParams = new KeyEncryptionParameters();
        kekParams.setEncryptionCredential(credential);
        kekParams.setAlgorithm(keyEncryptionAlgorithm);

        if (useSha256Digest) {
            RSAOAEPParameters rsaoaepParams = new RSAOAEPParameters();
            rsaoaepParams.setDigestMethod(EncryptionConstants.ALGO_ID_DIGEST_SHA256);
            kekParams.setRSAOAEPParameters(rsaoaepParams);
        }

        Encrypter encrypter = new Encrypter(encParams, kekParams);
        encrypter.setKeyPlacement(keyPlacement);

        return encrypter;
    }
}
