package uk.gov.ida.saml.core.test.builders;

import com.google.common.base.Optional;
import org.joda.time.DateTime;
import org.opensaml.saml.saml2.core.Attribute;
import uk.gov.ida.saml.core.IdaConstants;
import uk.gov.ida.saml.core.OpenSamlXmlObjectFactory;
import uk.gov.ida.saml.core.extensions.Gender;

import static com.google.common.base.Optional.fromNullable;

public class GenderAttributeBuilder_1_1 {

    private OpenSamlXmlObjectFactory openSamlXmlObjectFactory = new OpenSamlXmlObjectFactory();

    private Optional<DateTime> from = Optional.absent();
    private Optional<DateTime> to = Optional.absent();
    private Optional<String> value = Optional.absent();
    private boolean verified = false;

    public static GenderAttributeBuilder_1_1 aGender_1_1() {
        return new GenderAttributeBuilder_1_1();
    }

    public Attribute build() {

        Attribute genderAttribute = openSamlXmlObjectFactory.createAttribute();
        genderAttribute.setFriendlyName(IdaConstants.Attributes_1_1.Gender.FRIENDLY_NAME);
        genderAttribute.setName(IdaConstants.Attributes_1_1.Gender.NAME);
        genderAttribute.setNameFormat(Attribute.UNSPECIFIED);

        Gender genderAttributeValue = openSamlXmlObjectFactory.createGenderAttributeValue(value.or("Male"));

        if (from.isPresent()) {
            genderAttributeValue.setFrom(from.get());
        }
        if (to.isPresent()) {
            genderAttributeValue.setTo(to.get());
        }

        genderAttributeValue.setVerified(verified);

        genderAttribute.getAttributeValues().add(genderAttributeValue);

        return genderAttribute;
    }

    public GenderAttributeBuilder_1_1 withFrom(DateTime from) {
        this.from = Optional.fromNullable(from);
        return this;
    }

    public GenderAttributeBuilder_1_1 withTo(DateTime to) {
        this.to = Optional.fromNullable(to);
        return this;
    }

    public GenderAttributeBuilder_1_1 withValue(String name) {
        this.value = fromNullable(name);
        return this;
    }

    public GenderAttributeBuilder_1_1 withVerified(boolean verified) {
        this.verified = verified;
        return this;
    }
}
