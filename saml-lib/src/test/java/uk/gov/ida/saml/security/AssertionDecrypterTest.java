package uk.gov.ida.saml.security;

import net.shibboleth.utilities.java.support.collection.LockableClassToInstanceMultiMap;
import org.apache.commons.codec.binary.Base64;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.core.xml.Namespace;
import org.opensaml.core.xml.NamespaceManager;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.schema.XSBooleanValue;
import org.opensaml.core.xml.util.IDIndex;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.encryption.CarriedKeyName;
import org.opensaml.xmlsec.encryption.CipherData;
import org.opensaml.xmlsec.encryption.EncryptedKey;
import org.opensaml.xmlsec.encryption.EncryptionMethod;
import org.opensaml.xmlsec.encryption.EncryptionProperties;
import org.opensaml.xmlsec.encryption.ReferenceList;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.w3c.dom.Element;
import uk.gov.ida.common.shared.security.PrivateKeyFactory;
import uk.gov.ida.common.shared.security.PublicKeyFactory;
import uk.gov.ida.common.shared.security.X509CertificateFactory;
import uk.gov.ida.saml.core.api.CoreTransformersFactory;
import uk.gov.ida.saml.core.test.TestCertificateStrings;
import uk.gov.ida.saml.core.test.TestEntityIds;
import uk.gov.ida.saml.deserializers.StringToOpenSamlObjectTransformer;
import uk.gov.ida.saml.deserializers.validators.ResponseSizeValidator;
import uk.gov.ida.saml.security.exception.SamlFailedToDecryptException;
import uk.gov.ida.saml.security.saml.OpenSAMLMockitoRunner;
import uk.gov.ida.saml.security.saml.TestCredentialFactory;
import uk.gov.ida.saml.security.saml.builders.EncryptedAssertionBuilder;
import uk.gov.ida.saml.security.saml.builders.ResponseBuilder;
import uk.gov.ida.saml.security.validators.ValidatedResponse;
import uk.gov.ida.saml.security.validators.encryptedelementtype.EncryptionAlgorithmValidator;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.xml.namespace.QName;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import static junit.framework.TestCase.assertEquals;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.ida.saml.security.saml.builders.EncryptedAssertionBuilder.anEncryptedAssertionBuilder;
import static uk.gov.ida.saml.security.saml.builders.IssuerBuilder.anIssuer;
import static uk.gov.ida.saml.security.saml.builders.ResponseBuilder.aResponse;
import static uk.gov.ida.saml.security.saml.builders.ResponseBuilder.aResponseWithNoEncryptedAssertions;

@RunWith(OpenSAMLMockitoRunner.class)
public class AssertionDecrypterTest {

    private final String assertionId = "test-assertion";
    private IdaKeyStoreCredentialRetriever keyStoreCredentialRetriever;
    private AssertionDecrypter assertionDecrypter;
    private PublicKeyFactory publicKeyFactory;
    private SecretKeyEncrypter hubSecretKeyEncrypter = setupHubSecretKeyEncrypter();

    @Before
    public void setUp() {
        publicKeyFactory = new PublicKeyFactory(new X509CertificateFactory());
        PrivateKey privateKey = new PrivateKeyFactory().createPrivateKey(Base64.decodeBase64(TestCertificateStrings.PRIVATE_SIGNING_KEYS.get(
                TestEntityIds.HUB_ENTITY_ID)));
        PublicKey publicKey = publicKeyFactory.createPublicKey(TestCertificateStrings.getPrimaryPublicEncryptionCert(TestEntityIds.HUB_ENTITY_ID));

        PrivateKey privateEncryptionKey = new PrivateKeyFactory().createPrivateKey(Base64.decodeBase64(TestCertificateStrings.HUB_TEST_PRIVATE_ENCRYPTION_KEY));
        PublicKey publicEncryptionKey = publicKeyFactory.createPublicKey(TestCertificateStrings.HUB_TEST_PUBLIC_ENCRYPTION_CERT);

        KeyPair encryptionKeyPair = new KeyPair(publicEncryptionKey, privateEncryptionKey);

        keyStoreCredentialRetriever = new IdaKeyStoreCredentialRetriever(
                new IdaKeyStore(new KeyPair(publicKey, privateKey), Arrays.asList(encryptionKeyPair))
        );
        List<Credential> credentials = keyStoreCredentialRetriever.getDecryptingCredentials();
        Decrypter decrypter = new DecrypterFactory().createDecrypter(credentials);
        assertionDecrypter = new AssertionDecrypter(new EncryptionAlgorithmValidator(), decrypter);
    }

    @Test
    public void shouldConvertEncryptedAssertionIntoAssertion() throws Exception {
        final Response response = responseForAssertion(EncryptedAssertionBuilder.anEncryptedAssertionBuilder().withPublicEncryptionCert(TestCertificateStrings.HUB_TEST_PUBLIC_ENCRYPTION_CERT).withId(assertionId).build());

        final List<Assertion> assertions = assertionDecrypter.decryptAssertions(new ValidatedResponse(response));

        assertEquals(assertions.get(0).getID(), assertionId);
    }

    @Test
    public void shouldProvideOneReEncryptedSymmetricKey() throws Exception {
        final Response response = responseForAssertion(anEncryptedAssertionBuilder().withPublicEncryptionCert(TestCertificateStrings.HUB_TEST_PUBLIC_ENCRYPTION_CERT).withId(assertionId).build());

        final List<String> base64EncryptedSymmetricKeys = assertionDecrypter.getReEncryptedKeys(new ValidatedResponse(response), hubSecretKeyEncrypter, TestEntityIds.HUB_ENTITY_ID);

        assertThat(base64EncryptedSymmetricKeys.size()).isEqualTo(1);
    }

    @Test
    public void shouldProvideReEncryptedKeyWhenEncryptedKeyNestedInEncryptedData() {
        final Response response = responseWithEncryptedKeyNestedInEncryptedData();

        final List<String> base64EncryptedSymmetricKeys = assertionDecrypter.getReEncryptedKeys(new ValidatedResponse(response), hubSecretKeyEncrypter, TestEntityIds.HUB_ENTITY_ID);

        assertThat(base64EncryptedSymmetricKeys.size()).isEqualTo(1);
    }
    
    @Test
    public void shouldProvideThreeReEncryptedSymmetricKeys() throws Exception {
        final Response response = responseForMultipleAssertions(
                anEncryptedAssertionBuilder().withPublicEncryptionCert(TestCertificateStrings.HUB_TEST_PUBLIC_ENCRYPTION_CERT).withId(assertionId).build(),
                anEncryptedAssertionBuilder().withPublicEncryptionCert(TestCertificateStrings.HUB_TEST_PUBLIC_ENCRYPTION_CERT).withId(assertionId).build(),
                anEncryptedAssertionBuilder().withPublicEncryptionCert(TestCertificateStrings.HUB_TEST_PUBLIC_ENCRYPTION_CERT).withId(assertionId).build());

        final List<String> base64EncryptedSymmetricKeys = assertionDecrypter.getReEncryptedKeys(new ValidatedResponse(response), hubSecretKeyEncrypter, TestEntityIds.HUB_ENTITY_ID);

        assertThat(base64EncryptedSymmetricKeys.size()).isEqualTo(3);
    }

    @Test
    public void shouldProvideZeroReEncryptedSymmetricKeys() throws Exception {
        final Response response = responseWithZeroEncryptedAssertions();

        final List<String> base64EncryptedSymmetricKeys = assertionDecrypter.getReEncryptedKeys(new ValidatedResponse(response), hubSecretKeyEncrypter, TestEntityIds.HUB_ENTITY_ID);

        assertThat(base64EncryptedSymmetricKeys.size()).isEqualTo(0);
    }

    @Test(expected = SamlFailedToDecryptException.class)
    public void shouldThrowExceptionIfNoKeyCanBeDecrypted() throws MarshallingException, SignatureException {
        final EncryptedAssertion badlyEncryptedAssertion = anEncryptedAssertionBuilder().withId(assertionId).withEncrypterCredential(
                new TestCredentialFactory(TestCertificateStrings.STUB_IDP_PUBLIC_PRIMARY_CERT, null).getEncryptingCredential()).build();
        final Response response = responseForAssertion(badlyEncryptedAssertion);

        assertionDecrypter.getReEncryptedKeys(new ValidatedResponse(response), hubSecretKeyEncrypter, TestEntityIds.HUB_ENTITY_ID);
    }

    @Test
    public void shouldNotThrowExceptionIfSomeKeyCanBeDecrypted() throws MarshallingException, SignatureException {
        EncryptedAssertion encryptedAssertion = anEncryptedAssertionBuilder().withPublicEncryptionCert(TestCertificateStrings.HUB_TEST_PUBLIC_ENCRYPTION_CERT).withId(assertionId).build();
        EncryptedKey validEncryptedKey = encryptedAssertion.getEncryptedKeys().get(0);
        BadEncryptedKey badEncryptedKey = new BadEncryptedKey(validEncryptedKey);
        encryptedAssertion.getEncryptedKeys().add(0, badEncryptedKey);
        final Response response = responseForMultipleAssertions(encryptedAssertion);

        final List<String> base64EncryptedSymmetricKeys = assertionDecrypter.getReEncryptedKeys(new ValidatedResponse(response), hubSecretKeyEncrypter, TestEntityIds.HUB_ENTITY_ID);

        assertThat(base64EncryptedSymmetricKeys.size()).isEqualTo(1);
    }

    @Test (expected = SamlFailedToDecryptException.class)
    public void throwsExceptionIfCannotDecryptAssertions() throws MarshallingException, SignatureException {
        final EncryptedAssertion badlyEncryptedAssertion = anEncryptedAssertionBuilder().withId(assertionId).withEncrypterCredential(
                new TestCredentialFactory(TestCertificateStrings.STUB_IDP_PUBLIC_PRIMARY_CERT, null).getEncryptingCredential()).build();
        final Response response = responseForAssertion(badlyEncryptedAssertion);

        assertionDecrypter.decryptAssertions(new ValidatedResponse(response));
    }

    private Response responseForAssertion(EncryptedAssertion encryptedAssertion) throws MarshallingException, SignatureException {
        return aResponse()
                .withSigningCredential(keyStoreCredentialRetriever.getSigningCredential())
                .withIssuer(anIssuer().withIssuerId(TestEntityIds.STUB_IDP_ONE).build())
                .addEncryptedAssertion(encryptedAssertion)
                .build();
    }

    private Response responseForMultipleAssertions(EncryptedAssertion ... encryptedAssertions) throws MarshallingException, SignatureException {
        ResponseBuilder aResponseBuilder = aResponse()
                .withSigningCredential(keyStoreCredentialRetriever.getSigningCredential())
                .withIssuer(anIssuer().withIssuerId(TestEntityIds.STUB_IDP_ONE).build());
                Arrays.stream(encryptedAssertions).forEach(aResponseBuilder::addEncryptedAssertion);
                return aResponseBuilder.build();
    }

    private Response responseWithZeroEncryptedAssertions() throws Exception {
        return aResponseWithNoEncryptedAssertions()
                .withSigningCredential(keyStoreCredentialRetriever.getSigningCredential())
                .withIssuer(anIssuer().withIssuerId(TestEntityIds.STUB_IDP_ONE).build())
                .build();
    }

    private Response responseWithEncryptedKeyNestedInEncryptedData() {
        String doctoredSpanishSamlResponse = "PD94bWwgdmVyc2lvbj0iMS4wIiA/Pgo8c2FtbDJwOlJlc3BvbnNlIENvbnNlbnQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpjb25zZW50Om9idGFpbmVkIiBEZXN0aW5hdGlvbj0iaHR0cHM6Ly93d3cuaW50ZWdyYXRpb24uc2lnbmluLnNlcnZpY2UuZ292LnVrOjQ0My9TQU1MMi9TU08vRWlkYXNSZXNwb25zZS9QT1NUIiBJRD0iX1VOZ1BlcW5vX3JBbWU0bEhFMHFIUEUzdDd3OTE3dmdILWJjUXZGZ1VnNW9vcGl2WWZyeDM3N1hZdmpPWGlZSyIgSW5SZXNwb25zZVRvPSJfMjIwOTlkMTItNWY0MS00YWNhLTk3MDItZjQzOTFjZmQ0MDk4IiBJc3N1ZUluc3RhbnQ9IjIwMTktMTEtMDRUMTQ6NDA6NDIuNTcwWiIgVmVyc2lvbj0iMi4wIiB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyIgeG1sbnM6ZWlkYXM9Imh0dHA6Ly9laWRhcy5ldXJvcGEuZXUvYXR0cmlidXRlcy9uYXR1cmFscGVyc29uIiB4bWxuczpzYW1sMj0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiIgeG1sbnM6c2FtbDJwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiPgo8c2FtbDI6SXNzdWVyIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6ZW50aXR5IiB4bWxuczpzYW1sMj0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI+aHR0cHM6Ly9zZS1laWRhcy5yZWRzYXJhLmVzL0VpZGFzTm9kZS9TZXJ2aWNlTWV0YWRhdGE8L3NhbWwyOklzc3Vlcj4KPGRzOlNpZ25hdHVyZSB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+CjxkczpTaWduZWRJbmZvPgo8ZHM6Q2Fub25pY2FsaXphdGlvbk1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPgo8ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxkc2lnLW1vcmUjcnNhLXNoYTUxMiIvPgo8ZHM6UmVmZXJlbmNlIFVSST0iI19VTmdQZXFub19yQW1lNGxIRTBxSFBFM3Q3dzkxN3ZnSC1iY1F2RmdVZzVvb3BpdllmcngzNzdYWXZqT1hpWUsiPgo8ZHM6VHJhbnNmb3Jtcz4KPGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+CjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz4KPC9kczpUcmFuc2Zvcm1zPgo8ZHM6RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjc2hhNTEyIi8+CjxkczpEaWdlc3RWYWx1ZT5VUzBjbEhHdTdNSnRRQnYzN0N2R2VDSW83VkJOdjBjYlVQU0RGa3djWmlmWkRXNWZ3UTJtbVIxSk54ZU53VURHQ3MzbE9iT01xbURlKzBOcy83cVJZQT09PC9kczpEaWdlc3RWYWx1ZT4KPC9kczpSZWZlcmVuY2U+CjwvZHM6U2lnbmVkSW5mbz4KPGRzOlNpZ25hdHVyZVZhbHVlPkxjcW5oTVlFSXRLbUlFWTN5bkNYTGRldzFPUzQwLzZjZ1RnS0didTZIUVJMTmorQzdFNThRK1BGeGlhU1Ztb1VHdktCN0xITDlsNlM1bURsc1VWRlVBM093Q05raUN1QXpqYmVqMFpoOGJLb1BzRVEyUWdvYmlRdmNtUHA3anRrTGhvNi9HOVRKY25FNEZZZENDemZ5OWJPbnkxcyt2d2hFa0RzKzhaeDNUNy9talRjdExpbjVsN0JXV0NJYUFvVnc1MzlHZFFFOFV4TGw1c3dOVThubjFrNGJTMFgyWmVpdlY5U2thT2NVNGUyekwveVNEZkk1cXg5Ujc5MTRjTExPWTJxWTg1R0QvQ2IvME9mYU1tM2tNL0UzaWxyUVNLV3VpNldwcHJmOFU1VWUxZHdlMElLd2lZbGhHdUU5WGQxc1FNWGVhd0Z2MFRDbUljWnpkdTZvZz09PC9kczpTaWduYXR1cmVWYWx1ZT4KPGRzOktleUluZm8+CjxkczpYNTA5RGF0YT4KPGRzOlg1MDlDZXJ0aWZpY2F0ZT5NSUlIc1RDQ0JwbWdBd0lCQWdJUURNQ3hSclp5L1JWY0U4aWpiK3NTdHpBTkJna3Foa2lHOXcwQkFRc0ZBREJITVFzd0NRWURWUVFHCkV3SkZVekVSTUE4R0ExVUVDZ3dJUms1TlZDMVNRMDB4SlRBakJnTlZCQXNNSEVGRElFTnZiWEJ2Ym1WdWRHVnpJRWx1Wm05eWJjT2gKZEdsamIzTXdIaGNOTVRneE1qRTBNVFV4TXpNNVdoY05NakV4TWpFME1UVXhNek00V2pDQjJqRUxNQWtHQTFVRUJoTUNSVk14RHpBTgpCZ05WQkFjTUJrMUJSRkpKUkRFd01DNEdBMVVFQ2d3blUwVkRVa1ZVUVZKSlFTQkVSU0JGVTFSQlJFOGdSRVVnUmxWT1EwbFBUaUJRClZVSk1TVU5CTVRVd013WURWUVFMREN4VFJVTlNSVlJCVWtsQklFZEZUa1ZTUVV3Z1JFVWdRVVJOU1U1SlUxUlNRVU5KVDA0Z1JFbEgKU1ZSQlRERVNNQkFHQTFVRUJSTUpVekk0TXpNd01ESkZNUmd3RmdZRFZRUmhEQTlXUVZSRlV5MVRNamd6TXpBd01rVXhJekFoQmdOVgpCQU1NR2xORlRFeFBJRVZPVkVsRVFVUWdVMGRCUkNCUVVsVkZRa0ZUTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCCkNnS0NBUUVBdmRPQi9tUkt6RkpTWktiRHJCdlpvb21vK1l1YytJS3I5dWlZSVJ2VGd6K3lFcXVjVlJlalJoTWpzSWgxTWlUMUdsUmIKK1Y5aVNUNnBSajd0L2FTOEg2U3F6aXpJeTc1NlRnc0p6OEdWUmJPZlgyQTFYQ041UUswRm85NkhtY0FEVmowMU0xOHplK1ZRejdZRwowUS9vbmJkeDVJWndObmN4T24zZTBmR3cyVEViODV3dXluaEJORDNjaTIzNDEremgvemhjSEVkMHJNWHY2TkprVGkyRGlTNWFWeDgvCm91NExqRnVtOUhtRkJySU9mYlZ2OHIrUTVXMXE0OTRIbFJxR3Evcm5UeUdpc3EzWUFDMmlFRS9jdEpKZjg2ZHphL2IwOGxiOXlGVCsKV0JtVzZaczVBYTNDdkk1K2RuR3JFSmsvTzN2K0ppQk1hRGFNemt3Rlo4TmtDUUlEQVFBQm80SUVBekNDQS84d0RBWURWUjBUQVFILwpCQUl3QURDQmdRWUlLd1lCQlFVSEFRRUVkVEJ6TURzR0NDc0dBUVVGQnpBQmhpOW9kSFJ3T2k4dmIyTnpjR052YlhBdVkyVnlkQzVtCmJtMTBMbVZ6TDI5amMzQXZUMk56Y0ZKbGMzQnZibVJsY2pBMEJnZ3JCZ0VGQlFjd0FvWW9hSFIwY0RvdkwzZDNkeTVqWlhKMExtWnUKYlhRdVpYTXZZMlZ5ZEhNdlFVTkRUMDFRTG1OeWREQ0NBVFFHQTFVZElBU0NBU3N3Z2dFbk1JSUJHQVlLS3dZQkJBR3NaZ01KRXpDQwpBUWd3S1FZSUt3WUJCUVVIQWdFV0hXaDBkSEE2THk5M2QzY3VZMlZ5ZEM1bWJtMTBMbVZ6TDJSd1kzTXZNSUhhQmdnckJnRUZCUWNDCkFqQ0J6UXlCeWtObGNuUnBabWxqWVdSdklHTjFZV3hwWm1sallXUnZJR1JsSUhObGJHeHZJR1ZzWldOMGNzT3pibWxqYnlCelpXZkQKdW00Z2NtVm5iR0Z0Wlc1MGJ5QmxkWEp2Y0dWdklHVkpSRUZUTGlCVGRXcGxkRzhnWVNCc1lYTWdZMjl1WkdsamFXOXVaWE1nWkdVZwpkWE52SUdWNGNIVmxjM1JoY3lCbGJpQnNZU0JFVUVNZ1pHVWdSazVOVkMxU1EwMGdZMjl1SUU1SlJqb2dVVEk0TWpZd01EUXRTaUFvClF5OUtiM0puWlNCS2RXRnVJREV3TmkweU9EQXdPUzFOWVdSeWFXUXRSWE53WWNPeFlTa3dDUVlIQkFDTDdFQUJBVEE0QmdOVkhSRUUKTVRBdnBDMHdLekVwTUNjR0NTc0dBUVFCckdZQkNBd2FVMFZNVEU4Z1JVNVVTVVJCUkNCVFIwRkVJRkJTVlVWQ1FWTXdFd1lEVlIwbApCQXd3Q2dZSUt3WUJCUVVIQXdJd0RnWURWUjBQQVFIL0JBUURBZ1R3TUIwR0ExVWREZ1FXQkJSL1dWbXBSTGF3bEh4ZXdDNGxKc3F0CkVnUUVOekNCc0FZSUt3WUJCUVVIQVFNRWdhTXdnYUF3Q0FZR0JBQ09SZ0VCTUFzR0JnUUFqa1lCQXdJQkR6QVRCZ1lFQUk1R0FRWXcKQ1FZSEJBQ09SZ0VHQWpCeUJnWUVBSTVHQVFVd2FEQXlGaXhvZEhSd2N6b3ZMM2QzZHk1alpYSjBMbVp1YlhRdVpYTXZjR1J6TDFCRQpVMTlEVDAxUVgyVnpMbkJrWmhNQ1pYTXdNaFlzYUhSMGNITTZMeTkzZDNjdVkyVnlkQzVtYm0xMExtVnpMM0JrY3k5UVJGTmZRMDlOClVGOWxiaTV3WkdZVEFtVnVNQjhHQTFVZEl3UVlNQmFBRkJuNFdDOFUxcWJNbXdTWUNBMU0xNnNBcDRObE1JSGdCZ05WSFI4RWdkZ3cKZ2RVd2dkS2dnYytnZ2N5R2daNXNaR0Z3T2k4dmJHUmhjR052YlhBdVkyVnlkQzVtYm0xMExtVnpMME5PUFVOU1RERXNUMVU5UVVNbApNakJEYjIxd2IyNWxiblJsY3lVeU1FbHVabTl5YldGMGFXTnZjeXhQUFVaT1RWUXRVa05OTEVNOVJWTS9ZMlZ5ZEdsbWFXTmhkR1ZTClpYWnZZMkYwYVc5dVRHbHpkRHRpYVc1aGNuay9ZbUZ6WlQ5dlltcGxZM1JqYkdGemN6MWpVa3hFYVhOMGNtbGlkWFJwYjI1UWIybHUKZElZcGFIUjBjRG92TDNkM2R5NWpaWEowTG1adWJYUXVaWE12WTNKc2MyTnZiWEF2UTFKTU1TNWpjbXd3RFFZSktvWklodmNOQVFFTApCUUFEZ2dFQkFKVkx5WjZsSjNmMDNjZ1RsbnVIYm5GY1VvOXEzZWU5NkVlNER4bTdNLzQ1ZndNVmFiRGl0VkxYQWNjY09KdnVoQTVMCkxNbkN4SGNLSkZVdTFSSjdIbXRhNFpkeXo0d3NzV1c5QUFYbEVzTm9LbzYxWFpCeUFrdkpyTzhZTk9LQmQ0SFRpRmVDVjU3NHRDZkYKUmpOZ0ZIYzk2T24zT2haOWFGRThCQ3ZDRjBXWXVNUXJRaW5qc0N6bUNJbkJTMmxHY29QYnQzZ2RPbkpXU29wK1dHWk12MWd1ZWFHRgp4clg4b1F6NjQvcmI5TzgyTjZac2NET1IvTCtnd2Z1TXJpWEwvdGIvcWx2VGFjSDNLNno5S1lzL1QyMFg0aUpCQk5obW5QLytEb1hoCmlLcTR3b3I1Y2Jtb29oNFVReG9yWUtSa3JkYytuckZJWWsvN3ltbi9aNitDVDdvPTwvZHM6WDUwOUNlcnRpZmljYXRlPgo8L2RzOlg1MDlEYXRhPgo8L2RzOktleUluZm8+CjwvZHM6U2lnbmF0dXJlPgo8c2FtbDJwOlN0YXR1cyB4bWxuczpzYW1sMnA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCI+CjxzYW1sMnA6U3RhdHVzQ29kZSBWYWx1ZT0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnN0YXR1czpTdWNjZXNzIi8+CjxzYW1sMnA6U3RhdHVzTWVzc2FnZT51cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6c3RhdHVzOlN1Y2Nlc3M8L3NhbWwycDpTdGF0dXNNZXNzYWdlPgo8L3NhbWwycDpTdGF0dXM+CjxzYW1sMjpFbmNyeXB0ZWRBc3NlcnRpb24geG1sbnM6c2FtbDI9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPgo8eGVuYzpFbmNyeXB0ZWREYXRhIElkPSJfNWE0ZTI5YjgyOTNhOTkwNzFhMmU0Y2ViMTY4ZmIwZTkiIFR5cGU9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI0VsZW1lbnQiIHhtbG5zOnhlbmM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jIyI+Cjx4ZW5jOkVuY3J5cHRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDA5L3htbGVuYzExI2FlczI1Ni1nY20iIHhtbG5zOnhlbmM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jIyIvPgo8ZHM6S2V5SW5mbyB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+Cjx4ZW5jOkVuY3J5cHRlZEtleSBJZD0iXzhkM2JkYmUwMjYwNzkyNjlkYTY4OWIzZTk0OTdlOTUyIiB4bWxuczp4ZW5jPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyMiPgo8eGVuYzpFbmNyeXB0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjcnNhLW9hZXAtbWdmMXAiIHhtbG5zOnhlbmM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jIyI+CjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjc2hhMSIgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiLz4KPC94ZW5jOkVuY3J5cHRpb25NZXRob2Q+CjxkczpLZXlJbmZvPgo8ZHM6WDUwOURhdGE+CjxkczpYNTA5Q2VydGlmaWNhdGU+TUlJRDJEQ0NBc0NnQXdJQkFnSVVhZGdaeFl2Y1RsUmtWallKa3hObklvQnFmL293RFFZSktvWklodmNOQVFFTApCUUF3Y1RFTE1Ba0dBMVVFQmhNQ1IwSXhEekFOQmdOVkJBZ1RCa3h2Ym1SdmJqRVBNQTBHQTFVRUJ4TUdURzl1ClpHOXVNUmN3RlFZRFZRUUtFdzVEWVdKcGJtVjBJRTltWm1salpURU1NQW9HQTFVRUN4TURSMFJUTVJrd0Z3WUQKVlFRREV4QkpSRUZRSUVOdmNtVWdRMEVnUkdWMk1DQVhEVEU0TVRJeU1ERTJNekF3TUZvWUR6SXhNVGd4TVRJMgpNVFl6TURBd1dqQjNNUXN3Q1FZRFZRUUdFd0pIUWpFUE1BMEdBMVVFQ0JNR1RHOXVaRzl1TVE4d0RRWURWUVFICkV3Wk1iMjVrYjI0eEZ6QVZCZ05WQkFvVERrTmhZbWx1WlhRZ1QyWm1hV05sTVF3d0NnWURWUVFMRXdOSFJGTXgKSHpBZEJnTlZCQU1URmtsRVFTQklkV0lnUlc1amNubHdkR2x2YmlCRVpYWXdnZ0VpTUEwR0NTcUdTSWIzRFFFQgpBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRQ2tMU0xCMTQrd3JmUCtXZFBTOE91R2VZRnh0Tk5XR2U4K1VVT0kwZXJOCi9SRXNMZTZrWTliSytncXFTWU44eDEwNmFYWEk3SHZOdXdMVzIzWGphVTdIRTdJYWpvaFR3eTFySGRESWdtOCsKVWw2ZnpnU010WHhITEt5NmxVU0ZyYndtRFhPdHY5Y2tKTytBVjl5VklPZ2V1L3JMcEk1ZU10SjhDNnpCaWpWRwpFa1I1TWlYSlVjUUVhR2xWbThBYmZLaDlSeXY2S21NRXQ1RmFzeFpYRndnUkVZN1c4bE1Ndy9OQXlCak8wUEVUCkNOaUQxbmx6T3RybVpaWk5BbEdhdDZaMkR0a3c2eXJrZFpNdUg4VnVIaHhRUWZ6ZExFcXZDVUdmSzYweDhiR1kKWDBsTkFlYUpEc0lLVFlZOSsyMDhTd0ZMSUdKMTB1UFN0UnZwRmQ0M1dubUpBZ01CQUFHallEQmVNQTRHQTFVZApEd0VCL3dRRUF3SUZJREFNQmdOVkhSTUJBZjhFQWpBQU1CMEdBMVVkRGdRV0JCU2htYWlzZ3pHYjZnQnU4eHZYCllUUWwyK05JMkRBZkJnTlZIU01FR0RBV2dCUU1HZmdSNk9pNk9kNmhmUm50eWlYdmNsN2ZRakFOQmdrcWhraUcKOXcwQkFRc0ZBQU9DQVFFQW5xUmt6a2VFOW9tK0hydGIrOEl4RFVDMmVzbDZzTWlyZDFaeHVhQm02b2ljeE8ydgo0eDJhZ3RRa1JPTElJdHZUcnYrWFoxRksvY3lIcnRVV2hiQVptZFNESjhYTXVKbERmaGcwNjdpK0ZPL3NhbjB6CnBFSG9leHMwRVFkQWk0bk1Dckk0cXJOeCtwM0x2ZnZ3Z1h1c2RObzJRSUcwalc1YnJZQ25XeGJQMVpHdGcwMHgKaFh2VzVvNjRIcGpaYlpZZkpFNkhtWTg4cTFLMlF2eHQ4WUdnT1RvN0NCNWtWNmY2SGJlODJ6NWVUYVRubTI3RgpvcVE4UkpXQTRBQkxyMVAwcEdGeTIwZkllRHEwK1Y2bWh2TGtWblV3Q1Q5N1hMOW5MbjErTGVadW51aEdhVFZWCjFlNzNOcGZrbDB0eGlDRXk1MHRqWTZMT1NFOWVjUmI1SmNUd3JBPT08L2RzOlg1MDlDZXJ0aWZpY2F0ZT4KPC9kczpYNTA5RGF0YT4KPC9kczpLZXlJbmZvPgo8eGVuYzpDaXBoZXJEYXRhIHhtbG5zOnhlbmM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jIyI+Cjx4ZW5jOkNpcGhlclZhbHVlPmpBTlRwRUFVak16Q0M5d3pySGpwaGRMcEhFeVFSeitPc25qc0wrcGhuVmJsdURYN1h2ZkF2TjdyTjF3M2FIYzRrd053SjI4Q3c4dHE4bGlxOGpSdFU4eVo4RS94bzRYclBCbElieEhoSC9tWXBuOUY5K21EM1p1TnNSRjNLZ0VZL2xaay9tU1ZqdTYrZm5PQVRPRFEwYmh5bFBTeW1RanhJL3V0WVdzcWF3NytEU3NSYXBmMVlTQk8zNXZPckdBYXNoSmFsUXRnKzRNeW5COHdSb3cxZXNmL254NGF5QmI5ZFZnOEF1a3NTTUJJaXNSdWpXNnVsNngzRFdFWWhGOU9xbm9EU2VBYU1VMmc5OTduZnZEUUZscnNVVUxPanE0Q3d3M2xiNkFEWWN4ZXVBYVpsaXM0b2kwVVVyUm1zc2Z2emJGRStKajZxeWV1REErcHdtelV2UT09PC94ZW5jOkNpcGhlclZhbHVlPgo8L3hlbmM6Q2lwaGVyRGF0YT4KPC94ZW5jOkVuY3J5cHRlZEtleT4KPC9kczpLZXlJbmZvPgo8eGVuYzpDaXBoZXJEYXRhIHhtbG5zOnhlbmM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jIyI+Cjx4ZW5jOkNpcGhlclZhbHVlPnhIZUFSRitNbE1LTU81bmFOclY2VmJ2ZTBzRXlYdWo0SnJmbkxNaUlqZE9HYTRFMm55bUdkMkxIVi9iYXc0MUNadGJEZnJkbDl2QkgKZFJuc0hQRjZEem9kUndIY0hrd1c2OWpKUzJ5RlpqaW9NQnJpdjNad1d6RFdkb0JiaUQyZ1d6M2Fqa3FkU29zQXRWdFRFemtJS0RUOQpPbjlyR282bFg5UHpZYnUwQU11cis5dDVYRU1PZ3BmclNNMkpIWmZWZmJuai92ak9SdHI0NW5aK0x4aXNIOVhpYlRKcVhBL3drK1dxCk1oMDhHWnZyMHA0bE5Gd0ZRT1dkZmNFd0JxcXE4WTkzdWZHeHFXSGZBS2J0Z1pzUDVuVlJrcFZzUHVqRFV1bkE5TzZqdkZtM25PZWoKY3Z6aGo2QkVUVis4SUMyOVU4U1NkMTZiSnRmR252WlBhakxoQ3JEWWJ2bUo0cXZPbVd1czZ0TStBU1U0eTRSaXJjZUxUbm9HaEdITwpWYnI4ZVVWa3lRY29jNkl5bDIxSERidWlXdTRjMUpLNnRhSzhVTjNuNHkvb1lQZU5NV0RiUW85eGgwVEp4T1JCREtzTHFreDV0ek5lCnludXF2dk9zVDRMcGtJRzJVRnBrTDJMK1RZd2FOYVF6dnRrWEFxNlkwUFp0d1NqNnFHOWNlZUFNMUJtRWxNTE1rNlhocmpnYk9kVjMKSHY5V3pGdUJsU3JIdTBUMXNBdWpPeXd3Y0lYalpQK3JRb2IrSjJCTGQvSmVxTDZyVUtEWm1QTlFISXFlMHRTT1hvZXNxaEMrL29IRQpiRHdkT3RLRis3UkZYakhvMm1IUmtSM3lST082aFRlQTNFOFBNS0RZVERPSEJpeFZBSHlYTG5OK3grZmFpNTJuZE9MTHliOTZleXdLClRmbzh0L2JSMHZKdHNlTXhuL0E1dHFMK2t5d1BPMU9OQUttU3VrU3N6WEFFdDI1dWN0NDJiR3IvK1oxeGdrZGNobTBzLy80cTBoL2oKMW0rak0zbnRjcnlIOWZyS1ZFVUJoMFdXeFV3NmEyakFjdUgvMHM5OW1JVHRlZjg5bEdHQ0ZVakFSWDljUFVLcVNNa0FTTVF6TXdXcQpoN1p5MmNPSDBYYytnM0dMTkZBT1hjUHE4KzlKbWZvRks2RVRWR1JsaUg4VFFCemM2dytEc3JwWlAvMytlZlN6NlBnMGMydTQyK1I5ClB2R0c0QS9LYlVsdVh6anBod1Bnck9DaGJQNzhGVk9KaUp6Z2pRZWJ4OWZvMlJyVTlhbFczRkUySVVvbXpkSEQrQWFIWEJrNkxKUlgKSk5XV2RLYnVDQkduRjY5cGFoUE04d2Y4TWlQa29iRWZ3dTQxTUZEYVdDSVovY1BxNndTenNkL285N1ZYRjRjdXBqbUJKa1I4M05QVgpXSTdjc2dUWGU4ZUlXVzdsQWE4TmRBYk5CSlIxNlZGNG5YRXhxckRCdlg2QUxvZVZ6TktGQUhXeGJCQktWR1VtQW50VFJuWkFlQWROCi90b2p5Q2pYNlhqK0lDdnhvZUI5OEFxT3J6ZDUyOEhvRUFQTi9wUnF1TTFCVTJMZjNINDh6dnhzVUtrNUN6OFY3a3R4VUlGNmYzM1kKRDZyc1VzbU1IVDVjNTAxakh1SXMxQUllM1FzcllUcGc2YVdsMzJGdWx1bXBSS2pQTjN4TktjTEtqd0licDdQYU5iL3NKM1JYcmUwcwpKclNKcjJRN05BTnUxc3VsS2tsNmU2bGJIZVQ4a3V5S0t0ZDNxaWh4eU93T2xPMEVVR3E2OS9LeUMyUGtONHJiT0g2UVlzeGkrYWFYClRIemk5UkJkeGZ3ZVdqZ1FzdEhsbkpzMmhHUWljNjZBaURpc0p2RVg4c094WVExVm94YTFaQjhuR3Z5TlFYUzArbDF5dGlOYndVMVYKMndhTnZzY1oxR0dZaEhpYjRvUjlYS0VjdVVLMStNTjlKaHlZK1o4UnRpMGdROEFtUUxsVm0wWHp4VU4wTUFZT0NWSFNsV3YrZC82TgpBOEVYYlBtdk4ralVuWFJXaHpJTnZzcTR1NU9EcTNRNDVMMVltNHgyUm9BUWQ1Y0lncnVmTzBjZXRRdUI1VSt5cGZTRHk4aHNVUktJCmxaMHN2aTlEZEo4MUdWOUxkNTJ0UXZsOXZ3YmVRWkVjc2JUZzdDWXlzUi9XYS91aDlDK1h2SDhIdUxud2s3bkEvK3NkOE5icHE5OUIKeWxJYW4vWG5pcHZ4Q1ZhaStvMDUvL1haNjNHUm0vY2ZtTlcveFg5QzIzZm9lUDIxUHROdlRlcEx1TlY2dm9rS3FVRjJmcy9CRFk4cAppVnJkNWI0R1ZtMmJBQWtGeWl5ME5XZkpHQXAxcVpkME9weWxyZ0gwYStsbHhrNndQTCtPWXhFQ2hrYWErWWhVMGc0YTJQdTNMVXVkCmxpQ3lISzJqQkY2VjEyQVRmU0EyZllndzB1YVc3S1JWaGkwZW4wUWdySmJpTm9PUmxOdWJEbmR5Nm4rUzlIb2licmlhTEVia2c1N2MKMUxjTS84Nkh5Skp5eFE1VFpTeGdrU1lTc1dNZXZnazIrNlFnRllzTFdEbE52aVlTdkRqdjhMUHM1cTFmQnlwYzZwVk5QYTZNS0RCMgpaT2JWWXlzamFmaHJNWkNCeUpTQVVrZThjTnpSVXNpSC9tSmNBMXNvSGVXaHp3SHczRUc5c0tocHRWdis1b2M3UVdNdWlRR3ZFVFJGCkQrZTZRZ3g5blQ5SWFBRFdKQTJBbXUrbVFvSjFaZ3FSLzV6ZUk1cjJEWEZCelhqWk9acElnSDNGa3FEYmhGLzZoVlVMSk55TEUxTGUKdUgrS3RpaU55c3lXb2RtSjBmUGF1ZWRMM09TZHpMOEJWTU5DaWZVSXZUNDFBT2NQdGdQRVc3dmIvTUxsZHJOamRDN0loaDA0Z0RIMwpDSmd3SGpjVmJLMi9jZHZhM3g3Z1RVaE02alZyRGdpVGZNMnZ4c0h4VENQRU41SWV0Sm9jbzhCVm5LSTV4Nmx6Z2ptbG1GZi9zMEIrCnlCK3hjM1IwVjZsaWxTczRwN0dhOVVSMmJtQjhxZk8zdW1RNnNkRUZ1UE5SY01iZE10TloydXpFZXV2RWlMcUExT3VkaW1GbncraWMKaFpnZnV2ODRPNGluaE1qYjl2L1h6Tmo2azlISzAxK29nNUxFS2N4b2wrSXFnT3ZaeE15Q0srRXRIUjRZWUZHY1JnWXV4QmZyeitCRAptd01BSjVHZzZuNUZzZ294NFl5YzkzUzU3cjdDWktyRzFidExFbFNjUHhXb3M0cVByVmxia3B4RFVSWEFwTnFVTlRiQTczaG42d0ZlCnVyUUlTQU1mdXJRV1JTalJlL2MyTWxRZnBlMnRtYU44LzdQdk1DM2QvMTNKVWpKNnRwMXNmWXkyK0hBbmlJM2E2eHFtaStQUjNIM0YKZVgxemZjOGNwdzg2cW95Y0lnS2tQaGk4VElYMkp2akpCc3RrQjAzVkdnSUxqNDdGU05tZnhjQURsdFYzZUN2L1JncHlSOHpvU1dUSQptdURFdGpvbmNtTm1qTHpLeFhzQW04NHd3OUZ2OG9tOWxSVUYzL0J4T1hZRE1zTW9nNUx3aVhDeWVnb200V2lLV1FraGdIQjFKVzMvClMrZGttOXBodnZPTVNMc2NhMU5IbHFENEhoNkhXUk9rTlB1UWFxMExzZHFKTDVST3B1dmhmT1h1UHc3dy9LSk9YaUxOSEFIcVBJYzUKWDRpVGp3NTd5bFBWU2xTTHJtVU9tZ1pOem5seUxUeXEwSnIveGQvUnVMQjF0OWg3TXRMN29SdTVKRmduSWRCWFYwcWxCb21KNWFTaQozYXR5eHE1cnFEV1JSaElHby9aaEZmV1ptbmc5ZDNzUXF2SFNPVlR5cDZ4S2NidzBNNk1SVHQ5cG5BTy9WT0IrSnIzcWRLRXUycXI3CkhDdGhxYVhTa3FMRDdUNHpQK0JPY2I0PTwveGVuYzpDaXBoZXJWYWx1ZT4KPC94ZW5jOkNpcGhlckRhdGE+CjwveGVuYzpFbmNyeXB0ZWREYXRhPgo8L3NhbWwyOkVuY3J5cHRlZEFzc2VydGlvbj4KPC9zYW1sMnA6UmVzcG9uc2U+Cgo=";
        StringToOpenSamlObjectTransformer<Response> transformer = new CoreTransformersFactory().getStringtoOpenSamlObjectTransformer(new ResponseSizeValidator());
        return transformer.apply(doctoredSpanishSamlResponse);
    }

    private SecretKeyEncrypter setupHubSecretKeyEncrypter() {
        KeyStoreBackedEncryptionCredentialResolver credentialResolver = mock(KeyStoreBackedEncryptionCredentialResolver.class);
        Credential credential = new TestCredentialFactory(TestCertificateStrings.HUB_TEST_PUBLIC_ENCRYPTION_CERT, null).getEncryptingCredential();
        when(credentialResolver.getEncryptingCredential(TestEntityIds.HUB_ENTITY_ID)).thenReturn(credential);
        return new SecretKeyEncrypter(credentialResolver);
    }

    private class BadEncryptedKey implements EncryptedKey {
        /*
        * As convoluted as this seems, I think it's the most straightforward way to get a key that can't be decrypted
        * into an encrypted assertion.  I'd be delighted if there was a better way to do it.
         */
        private EncryptedKey validEncryptedKey;


        public BadEncryptedKey(EncryptedKey validEncryptedKey) {
            this.validEncryptedKey = validEncryptedKey;
        }

        @Override
        @Nullable
        public String getRecipient() {
            return validEncryptedKey.getRecipient();
        }

        @Override
        public void setRecipient(@Nullable String newRecipient) {
            validEncryptedKey.setRecipient(newRecipient);
        }

        @Override
        @Nullable
        public ReferenceList getReferenceList() {
            return validEncryptedKey.getReferenceList();
        }

        @Override
        public void setReferenceList(@Nullable ReferenceList newReferenceList) {
            validEncryptedKey.setReferenceList(newReferenceList);
        }

        @Override
        @Nullable
        public CarriedKeyName getCarriedKeyName() {
            return validEncryptedKey.getCarriedKeyName();
        }

        @Override
        public void setCarriedKeyName(@Nullable CarriedKeyName newCarriedKeyName) {
            validEncryptedKey.setCarriedKeyName(newCarriedKeyName);
        }

        @Override
        @Nullable
        public String getID() {
            return validEncryptedKey.getID();
        }

        @Override
        public void setID(@Nullable String newID) {
            validEncryptedKey.setID(newID);
        }

        @Override
        @Nullable
        public String getType() {
            return validEncryptedKey.getType();
        }

        @Override
        public void setType(@Nullable String newType) {
            validEncryptedKey.setType(newType);
        }

        @Override
        @Nullable
        public String getMimeType() {
            return validEncryptedKey.getMimeType();
        }

        @Override
        public void setMimeType(@Nullable String newMimeType) {
            validEncryptedKey.setMimeType(newMimeType);
        }

        @Override
        @Nullable
        public String getEncoding() {
            return validEncryptedKey.getEncoding();
        }

        @Override
        public void setEncoding(@Nullable String newEncoding) {
            validEncryptedKey.setEncoding(newEncoding);
        }

        @Override
        @Nullable
        public EncryptionMethod getEncryptionMethod() {
            EncryptionMethod mockEncryptionMethod = mock(EncryptionMethod.class);
            when(mockEncryptionMethod.getAlgorithm()).thenReturn("I'll eat my hat if this is a valid algorithm");
            return mockEncryptionMethod;
        }

        @Override
        public void setEncryptionMethod(@Nullable EncryptionMethod newEncryptionMethod) {
            validEncryptedKey.setEncryptionMethod(newEncryptionMethod);
        }

        @Override
        @Nullable
        public KeyInfo getKeyInfo() {
            return validEncryptedKey.getKeyInfo();
        }

        @Override
        public void setKeyInfo(@Nullable KeyInfo newKeyInfo) {
            validEncryptedKey.setKeyInfo(newKeyInfo);
        }

        @Override
        @Nullable
        public CipherData getCipherData() {
            return validEncryptedKey.getCipherData();
        }

        @Override
        public void setCipherData(@Nullable CipherData newCipherData) {
            validEncryptedKey.setCipherData(newCipherData);
        }

        @Override
        @Nullable
        public EncryptionProperties getEncryptionProperties() {
            return validEncryptedKey.getEncryptionProperties();
        }

        @Override
        public void setEncryptionProperties(@Nullable EncryptionProperties newEncryptionProperties) {
            validEncryptedKey.setEncryptionProperties(newEncryptionProperties);
        }

        @Override
        public void detach() {
            validEncryptedKey.detach();
        }

        @Override
        @Nullable
        public Element getDOM() {
            return validEncryptedKey.getDOM();
        }

        @Override
        @Nonnull
        public QName getElementQName() {
            return validEncryptedKey.getElementQName();
        }

        @Override
        @Nonnull
        public IDIndex getIDIndex() {
            return validEncryptedKey.getIDIndex();
        }

        @Override
        @Nonnull
        public NamespaceManager getNamespaceManager() {
            return validEncryptedKey.getNamespaceManager();
        }

        @Override
        @Nonnull
        public Set<Namespace> getNamespaces() {
            return validEncryptedKey.getNamespaces();
        }

        @Override
        @Nullable
        public String getNoNamespaceSchemaLocation() {
            return validEncryptedKey.getNoNamespaceSchemaLocation();
        }

        @Override
        @Nullable
        public List<XMLObject> getOrderedChildren() {
            return validEncryptedKey.getOrderedChildren();
        }

        @Override
        @Nullable
        public XMLObject getParent() {
            return validEncryptedKey.getParent();
        }

        @Override
        @Nullable
        public String getSchemaLocation() {
            return validEncryptedKey.getSchemaLocation();
        }

        @Override
        @Nullable
        public QName getSchemaType() {
            return validEncryptedKey.getSchemaType();
        }

        @Override
        public boolean hasChildren() {
            return validEncryptedKey.hasChildren();
        }

        @Override
        public boolean hasParent() {
            return validEncryptedKey.hasParent();
        }

        @Override
        public void releaseChildrenDOM(boolean propagateRelease) {
            validEncryptedKey.releaseChildrenDOM(propagateRelease);
        }

        @Override
        public void releaseDOM() {
            validEncryptedKey.releaseDOM();
        }

        @Override
        public void releaseParentDOM(boolean propagateRelease) {
            validEncryptedKey.releaseParentDOM(propagateRelease);
        }

        @Override
        @Nullable
        public XMLObject resolveID(@Nonnull String id) {
            return validEncryptedKey.resolveID(id);
        }

        @Override
        @Nullable
        public XMLObject resolveIDFromRoot(@Nonnull String id) {
            return validEncryptedKey.resolveIDFromRoot(id);
        }

        @Override
        public void setDOM(@Nullable Element dom) {
            validEncryptedKey.setDOM(dom);
        }

        @Override
        public void setNoNamespaceSchemaLocation(@Nullable String location) {
            validEncryptedKey.setNoNamespaceSchemaLocation(location);
        }

        @Override
        public void setParent(@Nullable XMLObject parent) {
            validEncryptedKey.setParent(parent);
        }

        @Override
        public void setSchemaLocation(@Nullable String location) {
            validEncryptedKey.setSchemaLocation(location);
        }

        @Override
        @Nullable
        public Boolean isNil() {
            return validEncryptedKey.isNil();
        }

        @Override
        @Nullable
        public XSBooleanValue isNilXSBoolean() {
            return validEncryptedKey.isNilXSBoolean();
        }

        @Override
        public void setNil(@Nullable Boolean newNil) {
            validEncryptedKey.setNil(newNil);
        }

        @Override
        public void setNil(@Nullable XSBooleanValue newNil) {
            validEncryptedKey.setNil(newNil);
        }

        @Override
        @Nonnull
        public LockableClassToInstanceMultiMap<Object> getObjectMetadata() {
            return validEncryptedKey.getObjectMetadata();
        }
    }
}

