package uk.gov.ida.saml.core.extensions.eidas.impl;

import net.shibboleth.utilities.java.support.xml.ElementSupport;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.common.AbstractSAMLObjectMarshaller;
import org.w3c.dom.Element;
import uk.gov.ida.saml.core.extensions.eidas.CountrySamlResponse;


public class CountrySamlResponseMarshaller extends AbstractSAMLObjectMarshaller {

    @Override
    protected void marshallElementContent(XMLObject samlObject, Element domElement) {
        CountrySamlResponse countrySamlResponse = (CountrySamlResponse) samlObject;
        ElementSupport.appendTextContent(domElement, countrySamlResponse.getValue());
    }
}
