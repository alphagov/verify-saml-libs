package uk.gov.ida.saml.core.transformers.outbound;

import org.opensaml.saml.saml2.core.Response;
import uk.gov.ida.saml.core.transformers.outbound.decorators.ResponseAssertionSigner;
import uk.gov.ida.saml.core.transformers.outbound.decorators.ResponseSignatureCreator;
import uk.gov.ida.saml.core.transformers.outbound.decorators.SamlSignatureSigner;
import uk.gov.ida.saml.serializers.XmlObjectToBase64EncodedStringTransformer;

import javax.inject.Inject;
import java.util.function.Function;

public class ResponseToSignedStringWithUnEncryptedAssertionsTransformer implements Function<Response, String> {
    protected final XmlObjectToBase64EncodedStringTransformer<?> xmlObjectToBase64EncodedStringTransformer;
    protected final SamlSignatureSigner<Response> samlSignatureSigner;
    protected final ResponseAssertionSigner responseAssertionSigner;
    protected final ResponseSignatureCreator responseSignatureCreator;

    @Inject
    public ResponseToSignedStringWithUnEncryptedAssertionsTransformer(
            XmlObjectToBase64EncodedStringTransformer<?> xmlObjectToBase64EncodedStringTransformer,
            SamlSignatureSigner<Response> samlSignatureSigner,
            ResponseAssertionSigner responseAssertionSigner,
            ResponseSignatureCreator responseSignatureCreator) {
        this.xmlObjectToBase64EncodedStringTransformer = xmlObjectToBase64EncodedStringTransformer;
        this.samlSignatureSigner = samlSignatureSigner;
        this.responseAssertionSigner = responseAssertionSigner;
        this.responseSignatureCreator = responseSignatureCreator;
    }

    @Override
    public String apply(final Response response) {
        final Response responseWithSignature = responseSignatureCreator.addUnsignedSignatureTo(response);
        final Response assertionSignedResponse = responseAssertionSigner.signAssertions(responseWithSignature);
        final Response signedResponse = samlSignatureSigner.sign(assertionSignedResponse);

        return xmlObjectToBase64EncodedStringTransformer.apply(signedResponse);
    }
}

