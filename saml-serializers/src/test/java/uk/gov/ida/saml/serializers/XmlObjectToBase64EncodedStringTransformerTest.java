package uk.gov.ida.saml.serializers;

import org.apache.commons.codec.binary.StringUtils;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

public class XmlObjectToBase64EncodedStringTransformerTest {

    private static final String REQUEST = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<saml2p:AuthnRequest Version=\"2.0\" xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\"/>";

    private XmlObjectToBase64EncodedStringTransformer xmlObjectToBase64EncodedStringTransformer;

    @Before
    public void setup() throws InitializationException {
        InitializationService.initialize();
        xmlObjectToBase64EncodedStringTransformer = new XmlObjectToBase64EncodedStringTransformer();
    }

    @Test
    @Ignore
    public void shouldTransformAuthnRequestToBase64EncodedString() throws Exception {
        AuthnRequest authnRequest = new AuthnRequestBuilder().buildObject();

        String encodedString = xmlObjectToBase64EncodedStringTransformer.apply(authnRequest);
        String decoded = StringUtils.newStringUtf8(Base64.getDecoder().decode(StringUtils.getBytesUtf8(encodedString)));
        assertThat(decoded).isEqualTo(REQUEST);
    }
}
