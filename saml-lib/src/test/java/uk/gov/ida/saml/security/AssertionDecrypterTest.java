package uk.gov.ida.saml.security;

import com.google.common.base.Charsets;
import com.google.common.io.Resources;
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
import uk.gov.ida.saml.security.saml.StringEncoding;
import uk.gov.ida.saml.security.saml.TestCredentialFactory;
import uk.gov.ida.saml.security.saml.builders.EncryptedAssertionBuilder;
import uk.gov.ida.saml.security.saml.builders.ResponseBuilder;
import uk.gov.ida.saml.security.validators.ValidatedResponse;
import uk.gov.ida.saml.security.validators.encryptedelementtype.EncryptionAlgorithmValidator;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.xml.namespace.QName;
import java.io.IOException;
import java.net.URL;
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
    public void shouldProvideReEncryptedKeyWhenEncryptedKeyNestedInEncryptedData() throws IOException {
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

    private Response responseWithEncryptedKeyNestedInEncryptedData() throws IOException {
        URL responseRequestUrl = getClass().getClassLoader().getResource("authnResponseNestedEncryptedKey.xml");
        String doctoredSpanishSamlResponse = StringEncoding.toBase64Encoded(Resources.toString(responseRequestUrl, Charsets.UTF_8));
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

