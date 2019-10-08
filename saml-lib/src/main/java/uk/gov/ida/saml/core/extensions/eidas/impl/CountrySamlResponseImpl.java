package uk.gov.ida.saml.core.extensions.eidas.impl;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.common.AbstractSAMLObject;
import uk.gov.ida.saml.core.extensions.eidas.CountrySamlResponse;

import javax.annotation.Nullable;
import java.util.List;

public class CountrySamlResponseImpl extends AbstractSAMLObject implements CountrySamlResponse {
    private String countrySamlResponse;

    protected CountrySamlResponseImpl(String namespaceURI, String elementLocalName, String namespacePrefix) {
        super(namespaceURI, elementLocalName, namespacePrefix);
    }

    @Override
    public String getValue() {
        return countrySamlResponse;
    }

    @Override
    public void setValue(String value) {
        countrySamlResponse = prepareForAssignment(countrySamlResponse, value);
    }

    @Nullable
    @Override
    public List<XMLObject> getOrderedChildren() {
        return null;
    }
}
