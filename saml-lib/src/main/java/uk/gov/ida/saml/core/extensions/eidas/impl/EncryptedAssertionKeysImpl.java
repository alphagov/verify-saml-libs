package uk.gov.ida.saml.core.extensions.eidas.impl;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.common.AbstractSAMLObject;
import uk.gov.ida.saml.core.extensions.eidas.EncryptedAssertionKeys;

import javax.annotation.Nullable;
import java.util.List;

public class EncryptedAssertionKeysImpl extends AbstractSAMLObject implements EncryptedAssertionKeys {
    private String encryptedAssertionKeys;

    protected EncryptedAssertionKeysImpl(String namespaceURI, String elementLocalName, String namespacePrefix) {
        super(namespaceURI, elementLocalName, namespacePrefix);
    }

    @Override
    public String getValue() {
        return encryptedAssertionKeys;
    }

    @Override
    public void setValue(String value) {
        encryptedAssertionKeys = prepareForAssignment(encryptedAssertionKeys, value);
    }

    @Nullable
    @Override
    public List<XMLObject> getOrderedChildren() {
        return null;
    }
}
