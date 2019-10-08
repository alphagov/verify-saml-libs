package uk.gov.ida.saml.core.extensions.eidas;

import org.opensaml.saml.common.xml.SAMLConstants;
import uk.gov.ida.saml.core.IdaConstants;

import javax.xml.namespace.QName;

public interface CountrySamlResponse extends UnsignedAssertionAttributeValue {
    String DEFAULT_ELEMENT_LOCAL_NAME = "AttributeValue";
    QName DEFAULT_ELEMENT_NAME = new QName(SAMLConstants.SAML20_NS, DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML20_PREFIX);
    String TYPE_LOCAL_NAME = "CountrySamlResponseType";
    QName TYPE_NAME = new QName(IdaConstants.IDA_NS, TYPE_LOCAL_NAME, IdaConstants.IDA_PREFIX);
}
