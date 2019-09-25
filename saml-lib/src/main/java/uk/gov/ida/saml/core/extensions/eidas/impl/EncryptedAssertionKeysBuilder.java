package uk.gov.ida.saml.core.extensions.eidas.impl;

import org.opensaml.saml.common.AbstractSAMLObjectBuilder;
import uk.gov.ida.saml.core.extensions.eidas.EncryptedAssertionKeys;

public class EncryptedAssertionKeysBuilder extends AbstractSAMLObjectBuilder<EncryptedAssertionKeys> {
    public EncryptedAssertionKeys buildObject() { return buildObject(EncryptedAssertionKeys.DEFAULT_ELEMENT_NAME, EncryptedAssertionKeys.TYPE_NAME); }

    @Override
    public EncryptedAssertionKeys buildObject(String namespaceURI, String localName, String namespacePrefix) {
        return new EncryptedAssertionKeysImpl(namespaceURI, localName, namespacePrefix);
    }
}
