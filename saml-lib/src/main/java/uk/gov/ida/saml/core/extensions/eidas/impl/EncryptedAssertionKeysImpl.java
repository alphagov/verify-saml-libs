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

    public String getEncryptedAssertionKeys() { return encryptedAssertionKeys; }

    public void setEncryptedAssertionKeys(String s) { encryptedAssertionKeys = prepareForAssignment(encryptedAssertionKeys, s); }

    @Nullable
    @Override
    public List<XMLObject> getOrderedChildren() { return null; }
}
