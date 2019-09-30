package uk.gov.ida.saml.core.transformers.outbound;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.algorithm.descriptors.DigestSHA256;
import org.opensaml.xmlsec.algorithm.descriptors.SignatureRSASHA256;
import uk.gov.ida.saml.core.extensions.eidas.CountrySamlResponse;
import uk.gov.ida.saml.core.extensions.eidas.EncryptedAssertionKeys;
import uk.gov.ida.saml.core.test.OpenSAMLMockitoRunner;
import uk.gov.ida.saml.core.test.PrivateKeyStoreFactory;
import uk.gov.ida.saml.core.test.TestCertificateStrings;
import uk.gov.ida.saml.core.test.TestCredentialFactory;
import uk.gov.ida.saml.core.test.TestEntityIds;
import uk.gov.ida.saml.core.transformers.outbound.decorators.ResponseAssertionSigner;
import uk.gov.ida.saml.core.transformers.outbound.decorators.ResponseSignatureCreator;
import uk.gov.ida.saml.core.transformers.outbound.decorators.SamlSignatureSigner;
import uk.gov.ida.saml.deserializers.validators.Base64StringDecoder;
import uk.gov.ida.saml.security.IdaKeyStoreCredentialRetriever;
import uk.gov.ida.saml.security.SignatureFactory;
import uk.gov.ida.saml.security.saml.deserializers.SamlObjectParser;
import uk.gov.ida.saml.serializers.XmlObjectToBase64EncodedStringTransformer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;
import static uk.gov.ida.saml.core.test.builders.AssertionBuilder.aCountryResponseAssertion;
import static uk.gov.ida.saml.security.saml.builders.ResponseBuilder.aResponseWithNoEncryptedAssertions;
import static uk.gov.ida.shared.utils.string.StringEncoding.toBase64Encoded;

@RunWith(OpenSAMLMockitoRunner.class)
public class ResponseToSignedStringWithUnEncryptedAssertionsTransformerTest {
    @Mock
    private IdaKeyStoreCredentialRetriever keyStoreCredentialRetriever;

    @Test
    public void shouldSignResponseAndAssertionsAndBase64Encode() throws Exception {
        SignatureFactory signatureFactory = new SignatureFactory(
                keyStoreCredentialRetriever,
                new SignatureRSASHA256(),
                new DigestSHA256()
        );
        Credential hubSigningCredential = createHubSigningCredential();
        when(keyStoreCredentialRetriever.getSigningCredential()).thenReturn(hubSigningCredential);

        ResponseToSignedStringWithUnEncryptedAssertionsTransformer transformer = new ResponseToSignedStringWithUnEncryptedAssertionsTransformer(
                new XmlObjectToBase64EncodedStringTransformer<>(),
                new SamlSignatureSigner<>(),
                new ResponseAssertionSigner(signatureFactory),
                new ResponseSignatureCreator(signatureFactory)
        );

        Response response = aResponseWithNoEncryptedAssertions()
                .addAssertion(aCountryResponseAssertion().buildUnencrypted())
                .build();

        String base64TransformedResponse = transformer.apply(response);

        String decodedResponse = new Base64StringDecoder().decode(base64TransformedResponse);
        Response signedResponse = (Response) new SamlObjectParser().getSamlObject(decodedResponse);

        CountrySamlResponse countrySamlResponseValue = (CountrySamlResponse) signedResponse.getAssertions().get(0).getAttributeStatements().get(0).getAttributes().get(0).getAttributeValues().get(0);
        EncryptedAssertionKeys encryptedAssertionKeys = (EncryptedAssertionKeys) signedResponse.getAssertions().get(0).getAttributeStatements().get(0).getAttributes().get(1).getAttributeValues().get(0);
        
        assertThat(countrySamlResponseValue.getCountrySamlResponse()).isEqualTo("base64SamlResponse");
        assertThat(encryptedAssertionKeys.getEncryptedAssertionKeys()).isEqualTo("base64EncryptedAssertionKey");
        assertThat(signedResponse.getSignature()).isNotNull();
        assertThat(signedResponse.getAssertions().get(0).getSignature()).isNotNull();
    }


    private Credential createHubSigningCredential() {
        return new TestCredentialFactory(TestCertificateStrings.HUB_TEST_PUBLIC_SIGNING_CERT, toBase64Encoded(
                new PrivateKeyStoreFactory().create(TestEntityIds.HUB_ENTITY_ID).getSigningPrivateKey()
                        .getEncoded()
        )).getSigningCredential();
    }
}
