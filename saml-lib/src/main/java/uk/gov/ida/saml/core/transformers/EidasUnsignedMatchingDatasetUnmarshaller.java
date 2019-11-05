package uk.gov.ida.saml.core.transformers;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.xmlsec.encryption.EncryptedData;
import org.opensaml.xmlsec.encryption.support.Decrypter;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;
import uk.gov.ida.saml.core.IdaConstants;
import uk.gov.ida.saml.core.domain.MatchingDataset;
import uk.gov.ida.saml.core.extensions.eidas.UnsignedAssertionAttributeValue;
import uk.gov.ida.saml.core.validation.SamlTransformationErrorException;
import uk.gov.ida.saml.core.validation.assertion.ExceptionThrowingValidator;
import uk.gov.ida.saml.deserializers.StringToOpenSamlObjectTransformer;
import uk.gov.ida.saml.security.EidasValidatorFactory;
import uk.gov.ida.saml.security.SecretKeyDecryptorFactory;
import uk.gov.ida.saml.security.validators.ValidatedResponse;

import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Optional;

public class EidasUnsignedMatchingDatasetUnmarshaller extends EidasMatchingDatasetUnmarshaller {

    private static final Logger LOG = LoggerFactory.getLogger(EidasUnsignedMatchingDatasetUnmarshaller.class);

    private final SecretKeyDecryptorFactory secretKeyDecryptorFactory;
    private final StringToOpenSamlObjectTransformer<Response> stringToOpenSamlObjectTransformer;
    private final EidasValidatorFactory eidasValidatorFactory;
    private final ExceptionThrowingValidator<Assertion> validator;

    public EidasUnsignedMatchingDatasetUnmarshaller(
            SecretKeyDecryptorFactory secretKeyDecryptorFactory,
            StringToOpenSamlObjectTransformer<Response> stringToOpenSamlObjectTransformer,
            EidasValidatorFactory eidasValidatorFactory,
            ExceptionThrowingValidator<Assertion> validator) {
        this.secretKeyDecryptorFactory = secretKeyDecryptorFactory;
        this.stringToOpenSamlObjectTransformer = stringToOpenSamlObjectTransformer;
        this.eidasValidatorFactory = eidasValidatorFactory;
        this.validator = validator;
    }

    @Override
    public MatchingDataset fromAssertion(Assertion assertion) {
        List<AttributeStatement> attributeStatements = assertion.getAttributeStatements();
        if (attributeStatements.isEmpty()) {
            return null;
        }

        try {
            List<Attribute> attributes = attributeStatements.get(0).getAttributes();
            Optional<String> encryptedTransientSecretKey = getUnsignedAssertionAttributeValue(attributes, IdaConstants.Eidas_Attributes.UnsignedAssertions.EncryptedSecretKeys.NAME);
            Optional<String> eidasSaml = getUnsignedAssertionAttributeValue(attributes, IdaConstants.Eidas_Attributes.UnsignedAssertions.EidasSamlResponse.NAME);
            if (!encryptedTransientSecretKey.isPresent() || !eidasSaml.isPresent()) {
                throw new SamlTransformationErrorException("Missing assertion attribute value from eIDAS unsigned assertion", Level.ERROR);
            }

            Response response = stringToOpenSamlObjectTransformer.apply(eidasSaml.get());
            ValidatedResponse validatedResponse = eidasValidatorFactory.getValidatedResponse(response);
            Decrypter decrypter = secretKeyDecryptorFactory.createDecrypter(encryptedTransientSecretKey.get());
            Optional<EncryptedAssertion> encryptedAssertion = validatedResponse.getEncryptedAssertions().stream().findFirst();
            if (encryptedAssertion.isPresent()) {
                EncryptedData encryptedData = encryptedAssertion.get().getEncryptedData();
                Assertion eidasAssertion = (Assertion) decrypter.decryptData(encryptedData);
                validator.apply(eidasAssertion);
                return super.fromAssertion(eidasAssertion);
            } else {
                LOG.warn("Error unmarshalling eIDAS unsigned assertions, encrypted assertions not present");
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | DecryptionException | SamlTransformationErrorException | ExceptionThrowingValidator.ValidationException e) {
            LOG.warn("Error unmarshalling eIDAS unsigned assertions from eIDAS SAML Response", e);
        }
        return null;

    }

    private Optional<String> getUnsignedAssertionAttributeValue(List<Attribute> attributes, final String key) {
        Optional<XMLObject> value = attributes.stream()
                .filter(attribute -> key.equals(attribute.getName()))
                .flatMap(attribute -> attribute.getAttributeValues().stream())
                .filter(xmlObject -> xmlObject instanceof UnsignedAssertionAttributeValue)
                .findFirst();
        String result = null;
        if (value.isPresent()) {
            XMLObject xmlObject = value.get();
            result = ((UnsignedAssertionAttributeValue) xmlObject).getValue();
        } else {
            LOG.warn("Could not find unsigned assertion attribute with key " + key);
        }
        return Optional.ofNullable(result);
    }

}
