package uk.gov.ida.saml.security;

import org.bouncycastle.util.encoders.Base64;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.List;

import static javax.crypto.Cipher.SECRET_KEY;

public class SecretKeyDecryptorFactory {

    private final IdaKeyStoreCredentialRetriever idaKeyStoreCredentialRetriever;

    public SecretKeyDecryptorFactory(IdaKeyStoreCredentialRetriever idaKeyStoreCredentialRetriever) {
        this.idaKeyStoreCredentialRetriever = idaKeyStoreCredentialRetriever;
    }

    public Decrypter createDecrypter(String encryptedSecretKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        List<Credential> decryptingCredentials = idaKeyStoreCredentialRetriever.getDecryptingCredentials();
        PrivateKey privateKey = decryptingCredentials.get(0).getPrivateKey();
        Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
        cipher.init(Cipher.UNWRAP_MODE, privateKey);
        SecretKey transientKey = (SecretKey) cipher.unwrap(Base64.decode(encryptedSecretKey), cipher.getAlgorithm(), SECRET_KEY);
        BasicCredential basicCredential = new BasicCredential(transientKey);
        StaticKeyInfoCredentialResolver keyResolver = new StaticKeyInfoCredentialResolver(basicCredential);
        return new Decrypter(keyResolver, null, null);
    }
}
