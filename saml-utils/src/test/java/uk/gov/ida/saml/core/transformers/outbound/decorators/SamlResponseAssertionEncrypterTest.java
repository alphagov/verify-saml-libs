package uk.gov.ida.saml.core.transformers.outbound.decorators;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import uk.gov.ida.saml.core.test.OpenSAMLMockitoRunner;
import uk.gov.ida.saml.security.EncrypterFactory;
import uk.gov.ida.saml.security.EntityToEncryptForLocator;
import uk.gov.ida.saml.security.KeyStoreBackedEncryptionCredentialResolver;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.assertj.core.util.Lists.newArrayList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(OpenSAMLMockitoRunner.class)
public class SamlResponseAssertionEncrypterTest {

    private static final String REQUEST_ID = "request_id";
    private static final String ENTITY_ID = "some id";
    private static final String ENCRYPTION_EXCEPTION_MESSAGE = "BLAM!";

    @Mock
    private KeyStoreBackedEncryptionCredentialResolver credentialResolver;

    @Mock
    private EncrypterFactory encrypterFactory;

    @Mock
    private EntityToEncryptForLocator entityToEncryptForLocator;

    @Mock
    private Credential credential;

    @Mock
    private Response response;

    @Mock
    private Assertion assertion;

    @Mock
    private Encrypter encrypter;

    private SamlResponseAssertionEncrypter assertionEncrypter;

    @Before
    public void setUp() {
        when(response.getInResponseTo()).thenReturn(REQUEST_ID);
        when(entityToEncryptForLocator.fromRequestId(REQUEST_ID)).thenReturn(ENTITY_ID);
        when(credentialResolver.getEncryptingCredential(ENTITY_ID)).thenReturn(credential);
        List<Assertion> assertionList = spy(newArrayList(assertion));
        when(response.getAssertions()).thenReturn(assertionList);
        when(encrypterFactory.createEncrypter(credential)).thenReturn(encrypter);
        assertionEncrypter = new SamlResponseAssertionEncrypter(
            credentialResolver,
            encrypterFactory,
            entityToEncryptForLocator
        );
    }

    @Test
    public void shouldConvertAssertionIntoEncryptedAssertion() throws EncryptionException {
        EncryptedAssertion encryptedAssertion = mock(EncryptedAssertion.class);
        when(encrypter.encrypt(assertion)).thenReturn(encryptedAssertion);
        List<EncryptedAssertion> encryptedAssertionList = spy(new ArrayList<>());
        when(response.getEncryptedAssertions()).thenReturn(encryptedAssertionList);

        assertionEncrypter.encryptAssertions(response);

        verify(encryptedAssertionList, times(1)).add(encryptedAssertion);
    }

    @Test
    public void decorate_shouldWrapEncryptionAssertionInSamlExceptionWhenEncryptionFails() throws EncryptionException {
        EncryptionException encryptionException = new EncryptionException(ENCRYPTION_EXCEPTION_MESSAGE);
        when(encrypter.encrypt(assertion)).thenThrow(encryptionException);

        try {
            assertionEncrypter.encryptAssertions(response);
        } catch (Exception e) {
            assertThat(e.getCause()).isEqualTo(encryptionException);
            return;
        }
        fail("Should never get here");
    }
}
