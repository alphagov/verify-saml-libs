package uk.gov.ida.saml.core.test.builders;

import org.joda.time.LocalDate;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import uk.gov.ida.saml.core.IdaConstants;
import uk.gov.ida.saml.core.extensions.eidas.CountrySamlResponse;
import uk.gov.ida.saml.core.extensions.eidas.CurrentFamilyName;
import uk.gov.ida.saml.core.extensions.eidas.CurrentGivenName;
import uk.gov.ida.saml.core.extensions.eidas.DateOfBirth;
import uk.gov.ida.saml.core.extensions.eidas.EncryptedAssertionKeys;
import uk.gov.ida.saml.core.extensions.eidas.PersonIdentifier;
import uk.gov.ida.saml.core.extensions.eidas.impl.CountrySamlResponseBuilder;
import uk.gov.ida.saml.core.extensions.eidas.impl.CurrentFamilyNameBuilder;
import uk.gov.ida.saml.core.extensions.eidas.impl.CurrentGivenNameBuilder;
import uk.gov.ida.saml.core.extensions.eidas.impl.DateOfBirthBuilder;
import uk.gov.ida.saml.core.extensions.eidas.impl.EncryptedAssertionKeysBuilder;
import uk.gov.ida.saml.core.extensions.eidas.impl.PersonIdentifierBuilder;
import uk.gov.ida.saml.core.test.OpenSamlXmlObjectFactory;

import java.util.ArrayList;
import java.util.List;

public class AttributeStatementBuilder {

    private static OpenSamlXmlObjectFactory openSamlXmlObjectFactory = new OpenSamlXmlObjectFactory();
    private List<Attribute> attributes = new ArrayList<>();

    public static AttributeStatementBuilder anAttributeStatement() {
        return new AttributeStatementBuilder();
    }

    public static AttributeStatementBuilder anEidasAttributeStatement() {
        Attribute firstName = anAttribute(IdaConstants.Eidas_Attributes.FirstName.NAME);
        CurrentGivenName firstNameValue = new CurrentGivenNameBuilder().buildObject();
        firstNameValue.setFirstName("Joe");
        firstName.getAttributeValues().add(firstNameValue);

        Attribute familyName =  anAttribute(IdaConstants.Eidas_Attributes.FamilyName.NAME);
        CurrentFamilyName familyNameValue = new CurrentFamilyNameBuilder().buildObject();
        familyNameValue.setFamilyName("Bloggs");
        familyName.getAttributeValues().add(familyNameValue);

        Attribute personIdentifier =  anAttribute(IdaConstants.Eidas_Attributes.PersonIdentifier.NAME);
        PersonIdentifier personIdentifierValue = new PersonIdentifierBuilder().buildObject();
        personIdentifierValue.setPersonIdentifier("JB12345");
        personIdentifier.getAttributeValues().add(personIdentifierValue);

        Attribute dateOfBirth =  anAttribute(IdaConstants.Eidas_Attributes.DateOfBirth.NAME);
        DateOfBirth dateOfBirthValue = new DateOfBirthBuilder().buildObject();
        dateOfBirthValue.setDateOfBirth(LocalDate.now());
        dateOfBirth.getAttributeValues().add(dateOfBirthValue);

        return anAttributeStatement()
            .addAttribute(firstName)
            .addAttribute(familyName)
            .addAttribute(personIdentifier)
            .addAttribute(dateOfBirth);
    }

    public static AttributeStatementBuilder aCountryResponseAttributeStatement() {
        Attribute countrySamlResponse = anAttribute(IdaConstants.Eidas_Attributes.UnsignedAssertions.EidasSamlResponse.NAME);
        CountrySamlResponse countrySamlResponseValue = new CountrySamlResponseBuilder().buildObject();
        countrySamlResponseValue.setCountrySamlResponse("base64SamlResponse");
        countrySamlResponse.getAttributeValues().add(countrySamlResponseValue);

        Attribute encryptedAssertionKeys = anAttribute(IdaConstants.Eidas_Attributes.UnsignedAssertions.EncryptedSecretKeys.NAME);
        EncryptedAssertionKeys encryptedAssertionKeysValue = new EncryptedAssertionKeysBuilder().buildObject();
        encryptedAssertionKeysValue.setEncryptedAssertionKeys("base64EncryptedAssertionKey");
        encryptedAssertionKeys.getAttributeValues().add(encryptedAssertionKeysValue);

        return anAttributeStatement()
                .addAttribute(countrySamlResponse)
                .addAttribute(encryptedAssertionKeys);
    }

    private static Attribute anAttribute(String name) {
        Attribute attribute = openSamlXmlObjectFactory.createAttribute();
        attribute.setName(name);
        return attribute;
    }

    public AttributeStatement build() {
        AttributeStatement attributeStatement = openSamlXmlObjectFactory.createAttributeStatement();

        attributeStatement.getAttributes().addAll(attributes);

        return attributeStatement;
    }

    public AttributeStatementBuilder addAttribute(Attribute attribute) {
        this.attributes.add(attribute);
        return this;
    }

    public AttributeStatementBuilder addAllAttributes(List<Attribute> attributes) {
        this.attributes.addAll(attributes);
        return this;
    }
}
