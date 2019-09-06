package uk.gov.ida.saml.security;

import org.apache.commons.ssl.util.PublicKeyDeriver;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.opensaml.security.credential.Credential;
import uk.gov.ida.saml.security.saml.OpenSAMLMockitoRunner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@RunWith(OpenSAMLMockitoRunner.class)
public class SecretKeyEncrypterTest {
    @Mock
    KeyStoreBackedEncryptionCredentialResolver credentialResolver;
    @Mock
    Credential mockCredential;

    private SecretKeyEncrypter testSubject;
    private static final String AN_ENTITY_ID = "ministry-of-pies";

    private static String base64RsaPrivateKey =
            "MIIEowIBAAKCAQEAzAmUBx0uNqYwzqH/56qh2VOPxC3Ip+As93MpTfbYi6voZGA0\n" +
            "DAHxhFIDoiVDvmyVM+WEARuUB4EF8FIPv8vcx63s192UBKv2PuIc0dikOObTMdjR\n" +
            "/7fnL++HHPc45tlThaVyT4PLUAw8ML9yaomHFb53wr/DXVi/DBTE3uCT+Uf1UJCX\n" +
            "DMZDS/kbMH4t90hmAigRobgnKDp5unuB5n5zh+VL6yk7sNRhHY8Xr3R5hYb/87Sy\n" +
            "t3P9z84+6JhacbZUR28eRl+zMauheiLtUmyo3VPfoGrCsS7mpWy4OzvfD7UeAv52\n" +
            "EuQJ+wINf94+BB7EKXiM939GSLb6Kw4TOc6m3wIDAQABAoIBAGjv/Cv0fBIrQyri\n" +
            "8qSJg5gse+Jf0bVVfIr/tZydeh3LmkgVmm8aiMaPD8NS+xZy7gG050FSl72MRCun\n" +
            "aOYxySkBcLBNC5Wjg5Av5raef0esn64hX0/vm31x6cGh/Kft2iEASFxQ4j4XLNW9\n" +
            "gPD+LnWmch29VpMp04g5Hk+qnTA1QI24CpMK1Dystz3b1mcfmnxfnQlFhEGB1atQ\n" +
            "hRqlTaiswZY9Eq45KLw03V21gh9Wxsze1xkuWW35yMIUv4sc9k4ZBQPvAHvaIdlW\n" +
            "otRgLyHQOixfiCYgGXFjLoA0dkbv5mjNpLyGLUL9XeuMgrIwUKNyVIFpEq9kvKTz\n" +
            "SmlibkECgYEA82dDW7idbm411iYT4G8SRSxXBdiDfETAG7gFLuty+vRCVVVJGjWO\n" +
            "u3qnoPCMhrjmiXtTyqHDGjTAtn6glUckHTayTkq6CLQa1aOjJbubUF4p/m7gMdTZ\n" +
            "wVorHEhE8DlHNyGki9JY0kMq8CLFwrtE0mMA3LaRnoMQ7tNsVpeDIA8CgYEA1pjG\n" +
            "KJNqeUX1yvfUV+4XheVHiKw/wowOz9YHjeEYzj/cD6RFUhxRyrhqnnqW1Y1DAwMs\n" +
            "hBKNAVh3EZEpiToXd7yyCL3OzDyP6uAcX7YGnxH/JlmN7yIs1ZCMktMO0s0WBDjs\n" +
            "FBHELrOVD5gqvQHUYOiMA2gXgOl8kyj30wyuPDECgYAjv0G0QcvVQRhlCBiZOJbN\n" +
            "U/K/6Al/gbVZHNCeEHRFiQQI9kqTL9RzklL2Hv30d0lcXaFzvAgkXCUFaFl7MwSJ\n" +
            "ydOsDet+hbz/LVYzn3by+bFfLbd9eg41CGIWeEKvqSndXfKFmnHzB2xR8jlrHQfB\n" +
            "gkrJH4MJbaRZ/vEFUqEuXwKBgQCjCZjrdOxczNEr7lPuph5LBOHvLWaXqQ8LykEd\n" +
            "Atp0wEGxxI1CD+/4Q1oFo397KYKzBDNK+EkWr55uw0m6T19LAhqE16gItS5mNPR5\n" +
            "pvKq4eJmwX07JEzJyLN0TVOixlumw5Rgvwq8rIVgPqyhwoUXRzYw1GGe+EVEDMkU\n" +
            "GDs70QKBgC65ybyZq6TIiS3t6FNpHOcItEDHOxn0sds0hIMbSOxN0fal/oPENTwF\n" +
            "DZcF7BqDilVuaFbkkHX0agKG6w+LuX8U/HfqLax6jxjwsNR34akknFvpDiIASpll\n" +
            "DjzEEarH/ZICQIGxynujKL7H/SCSFFFzPz+T91V/5aNPiI7VDwlc";

    private static PrivateKey privateKey;

    @Test
    public void shouldSuccessfullyEncryptASecretKey() throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.decode(base64RsaPrivateKey));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        privateKey = keyFactory.generatePrivate(keySpec);

        PublicKey publicKey = PublicKeyDeriver.derivePublicKey(privateKey);

        when(credentialResolver.getEncryptingCredential(AN_ENTITY_ID)).thenReturn(mockCredential);
        when(mockCredential.getPublicKey()).thenReturn(publicKey);

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

    private Key decryptSecretKey(String base64EncryptedSecretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, Base64DecodingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.UNWRAP_MODE, privateKey);
        return cipher.unwrap(Base64.decode(base64EncryptedSecretKey), "RSA", Cipher.SECRET_KEY);
    }

}
