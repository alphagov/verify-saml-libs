package uk.gov.ida.saml.core.transformers.outbound.decorators;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.xmlsec.signature.Signature;
import uk.gov.ida.saml.security.SignatureFactory;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class ResponseSignatureCreatorTest {

    private static final String RESPONSE_ID = "response-id";
    private ResponseSignatureCreator responseSignatureCreator;

    @Mock
    private Response response;

    @Mock
    private SignatureFactory signatureFactory;

    @Before
    public void setup() {
        responseSignatureCreator = new ResponseSignatureCreator(signatureFactory);
    }

    @Test
    public void shouldGetSignatureAndAssignIt() {
        when(response.getSignatureReferenceID()).thenReturn(RESPONSE_ID);

        responseSignatureCreator.addUnsignedSignatureTo(response);

        verify(signatureFactory).createSignature(RESPONSE_ID);
    }

    @Test
    public void shouldAssignSignatureToResponse() {
        Signature signature = mock(Signature.class);
        when(response.getSignatureReferenceID()).thenReturn(RESPONSE_ID);
        when(signatureFactory.createSignature(RESPONSE_ID)).thenReturn(signature);

        responseSignatureCreator.addUnsignedSignatureTo(response);

        verify(response).setSignature(signature);
    }
}
