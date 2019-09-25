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
import uk.gov.ida.saml.core.IdaConstants;
import uk.gov.ida.saml.core.domain.MatchingDataset;
import uk.gov.ida.saml.core.extensions.StringValueSamlObject;
import uk.gov.ida.saml.deserializers.StringToOpenSamlObjectTransformer;
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
    private final StringToOpenSamlObjectTransformer<Response> stringtoOpenSamlObjectTransformer;

    public EidasUnsignedMatchingDatasetUnmarshaller(
            SecretKeyDecryptorFactory secretKeyDecryptorFactory,
            StringToOpenSamlObjectTransformer<Response> stringtoOpenSamlObjectTransformer) {
        this.secretKeyDecryptorFactory = secretKeyDecryptorFactory;
        this.stringtoOpenSamlObjectTransformer = stringtoOpenSamlObjectTransformer;
    }

    @Override
    public MatchingDataset fromAssertion(Assertion assertion) {
        List<AttributeStatement> attributeStatements = assertion.getAttributeStatements();
        if (attributeStatements.isEmpty()) {
            return null;
        }

        try {

            List<Attribute> attributes = attributeStatements.get(0).getAttributes();
            Optional<String> encryptedTransientSecretKey = getAttributeStringValue(attributes, IdaConstants.Eidas_Attributes.UnsignedAssertions.EncryptedSecretKeys.NAME);
            Optional<String> eidasSaml = getAttributeStringValue(attributes, IdaConstants.Eidas_Attributes.UnsignedAssertions.EidasSamlResponse.NAME);
            if (!(encryptedTransientSecretKey.isPresent() && eidasSaml.isPresent())) {
                return null;
            }

            Response response = stringtoOpenSamlObjectTransformer.apply(eidasSaml.get());
            ValidatedResponse validatedResponse = new ValidatedResponse(response);
            Decrypter decrypter = secretKeyDecryptorFactory.createDecrypter(encryptedTransientSecretKey.get());
            Optional<EncryptedAssertion> encryptedAssertion = validatedResponse.getEncryptedAssertions().stream().findFirst();
            if (encryptedAssertion.isPresent()) {
                EncryptedData encryptedData = encryptedAssertion.get().getEncryptedData();
                return super.fromAssertion((Assertion) decrypter.decryptData(encryptedData));
            } else {
                LOG.warn("Error unmarshalling eIDAS unsigned assertions, encrypted assertions not present");
            }


        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | DecryptionException e) {
            LOG.warn("Error unmarshalling eIDAS unsigned assertions from eIDAS SAML Response", e);
        }
        return null;

    }

    private Optional<String> getAttributeStringValue(List<Attribute> attributes, final String key) {
        Optional<XMLObject> value = attributes.stream()
                .filter(attribute -> key.equals(attribute.getName()))
                .flatMap(attribute -> attribute.getAttributeValues().stream())
                .findFirst();
        String result = null;
        if (value.isPresent()) {
            XMLObject xmlObject = value.get();
            result = ((StringValueSamlObject) xmlObject).getValue();
        } else {
            LOG.warn("Could not find unsigned assertion attribute with key " + key);
        }
        return Optional.ofNullable(result);
    }

}
