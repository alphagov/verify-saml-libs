package uk.gov.ida.saml.core.extensions.eidas.impl;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.common.AbstractSAMLObjectUnmarshaller;
import uk.gov.ida.saml.core.extensions.eidas.EncryptedAssertionKeys;

public class EncryptedAssertionKeysUnmarshaller extends AbstractSAMLObjectUnmarshaller {
    @Override
    protected void processElementContent(XMLObject samlObject, String elementContent) {
        EncryptedAssertionKeys encryptedAssertionKeys = (EncryptedAssertionKeys) samlObject;
        encryptedAssertionKeys.setValue(elementContent);
    }
}
