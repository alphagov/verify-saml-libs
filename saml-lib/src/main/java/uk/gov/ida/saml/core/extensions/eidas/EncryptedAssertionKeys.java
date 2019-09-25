package uk.gov.ida.saml.core.extensions.eidas;

import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AttributeValue;
import uk.gov.ida.saml.core.IdaConstants;

import javax.xml.namespace.QName;


public interface EncryptedAssertionKeys extends AttributeValue {
    String DEFAULT_ELEMENT_LOCAL_NAME = "AttributeValue";
    QName DEFAULT_ELEMENT_NAME = new QName(SAMLConstants.SAML20_NS, DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML20_PREFIX);
    String TYPE_LOCAL_NAME = "EncryptedAssertionKeysType";
    QName TYPE_NAME = new QName(IdaConstants.IDA_NS, TYPE_LOCAL_NAME, IdaConstants.IDA_PREFIX);

    String getEncryptedAssertionKeys();

    void setEncryptedAssertionKeys(String countrySamlResponse);

}
