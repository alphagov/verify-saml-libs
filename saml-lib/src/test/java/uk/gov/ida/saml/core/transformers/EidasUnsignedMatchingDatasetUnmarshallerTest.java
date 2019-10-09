package uk.gov.ida.saml.core.transformers;

import com.google.common.collect.ImmutableList;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.xmlsec.encryption.EncryptedData;
import uk.gov.ida.saml.core.IdaConstants;
import uk.gov.ida.saml.core.domain.MatchingDataset;
import uk.gov.ida.saml.core.extensions.eidas.CountrySamlResponse;
import uk.gov.ida.saml.core.extensions.eidas.CurrentGivenName;
import uk.gov.ida.saml.core.extensions.eidas.EncryptedAssertionKeys;
import uk.gov.ida.saml.core.extensions.eidas.PersonIdentifier;
import uk.gov.ida.saml.deserializers.StringToOpenSamlObjectTransformer;
import uk.gov.ida.saml.security.SecretKeyDecryptorFactory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class EidasUnsignedMatchingDatasetUnmarshallerTest {

    @InjectMocks
    private EidasUnsignedMatchingDatasetUnmarshaller unmarshaller;

    @Mock
    private SecretKeyDecryptorFactory secretKeyDecryptorFactory;

    @Mock
    private StringToOpenSamlObjectTransformer<Response> stringtoOpenSamlObjectTransformer;

    @Mock
    private Assertion unsignedAssertion;

    @Mock
    private Assertion eidasAssertion;

    @Mock
    private AttributeStatement unsignedAttributeStatement;

    @Mock
    private AttributeStatement eidasAttributeStatement;

    @Mock
    private Attribute attributeEncryptionKeys;

    @Mock
    private Attribute firstName;

    @Mock
    private Attribute pid;

    @Mock
    private Attribute attributeEidasResponse;

    @Mock
    private EncryptedAssertionKeys attributeValueEncryptionKeys;

    @Mock
    private CountrySamlResponse attributeValueEidasResponse;

    @Mock
    private PersonIdentifier personIdentifierValue;

    @Mock
    private CurrentGivenName firstNameValue;

    @Mock
    private Response response;

    @Mock
    private Decrypter decrypter;

    @Mock
    private EncryptedAssertion encryptedAssertion;

    @Mock
    private EncryptedData encryptedData;

    @Test
    public void whenAssertionHasNoAttributeStatementsThenMatchingDatasetIsNull() {
        MatchingDataset matchingDataset = unmarshaller.fromAssertion(unsignedAssertion);
        assertThat(matchingDataset).isNull();
        verify(unsignedAssertion).getAttributeStatements();
        verifyZeroInteractions(stringtoOpenSamlObjectTransformer, secretKeyDecryptorFactory);
    }

    @Test
    public void whenNoEncryptionKeysAttributeThenMatchingDatasetIsNull() {
        when(unsignedAssertion.getAttributeStatements()).thenReturn(ImmutableList.of(unsignedAttributeStatement));
        when(unsignedAttributeStatement.getAttributes()).thenReturn(ImmutableList.of(attributeEncryptionKeys, attributeEidasResponse));
        when(attributeEncryptionKeys.getName()).thenReturn("no matching key");
        when(attributeEidasResponse.getName()).thenReturn(IdaConstants.Eidas_Attributes.UnsignedAssertions.EidasSamlResponse.NAME);
        MatchingDataset matchingDataset = unmarshaller.fromAssertion(unsignedAssertion);
        assertThat(matchingDataset).isNull();
        verify(attributeEncryptionKeys, times(2)).getName();
        verify(attributeEidasResponse, times(2)).getName();
        verify(attributeEidasResponse).getAttributeValues();
        verifyNoMoreInteractions(attributeEncryptionKeys, attributeEidasResponse);
        verifyZeroInteractions(stringtoOpenSamlObjectTransformer, secretKeyDecryptorFactory);
    }

    @Test
    public void whenNoEidasResponseAttributeThenMatchingDatasetIsNull() {
        when(unsignedAssertion.getAttributeStatements()).thenReturn(ImmutableList.of(unsignedAttributeStatement));
        when(unsignedAttributeStatement.getAttributes()).thenReturn(ImmutableList.of(attributeEncryptionKeys, attributeEidasResponse));
        when(attributeEncryptionKeys.getName()).thenReturn(IdaConstants.Eidas_Attributes.UnsignedAssertions.EncryptedSecretKeys.NAME);
        when(attributeEidasResponse.getName()).thenReturn("no matching key");
        MatchingDataset matchingDataset = unmarshaller.fromAssertion(unsignedAssertion);
        assertThat(matchingDataset).isNull();
        verify(attributeEncryptionKeys, times(2)).getName();
        verify(attributeEidasResponse, times(2)).getName();
        verify(attributeEncryptionKeys).getAttributeValues();
        verifyNoMoreInteractions(attributeEncryptionKeys, attributeEidasResponse);
        verifyZeroInteractions(stringtoOpenSamlObjectTransformer, secretKeyDecryptorFactory);
    }

    @Test
    public void shouldDelegateToMatchingDatasetUnmarshallerToUnpackEidasAssertions() throws Exception {

        when(unsignedAssertion.getAttributeStatements()).thenReturn(ImmutableList.of(unsignedAttributeStatement));
        when(eidasAssertion.getAttributeStatements()).thenReturn(ImmutableList.of(eidasAttributeStatement));
        when(unsignedAttributeStatement.getAttributes()).thenReturn(ImmutableList.of(attributeEncryptionKeys, attributeEidasResponse));
        when(eidasAttributeStatement.getAttributes()).thenReturn(ImmutableList.of(firstName, pid));
        when(attributeEncryptionKeys.getName()).thenReturn(IdaConstants.Eidas_Attributes.UnsignedAssertions.EncryptedSecretKeys.NAME);
        when(attributeEidasResponse.getName()).thenReturn(IdaConstants.Eidas_Attributes.UnsignedAssertions.EidasSamlResponse.NAME);
        when(firstName.getName()).thenReturn(IdaConstants.Eidas_Attributes.FirstName.NAME);
        when(pid.getName()).thenReturn(IdaConstants.Eidas_Attributes.PersonIdentifier.NAME);
        when(attributeEncryptionKeys.getAttributeValues()).thenReturn(ImmutableList.of(attributeValueEncryptionKeys));
        when(attributeEidasResponse.getAttributeValues()).thenReturn(ImmutableList.of(attributeValueEidasResponse));
        when(firstName.getAttributeValues()).thenReturn(ImmutableList.of(firstNameValue));
        when(firstNameValue.isLatinScript()).thenReturn(true);
        when(pid.getAttributeValues()).thenReturn(ImmutableList.of(personIdentifierValue));
        when(personIdentifierValue.getPersonIdentifier()).thenReturn("It's a me, Mario");
        when(attributeValueEncryptionKeys.getValue()).thenReturn("an encrypted  key string");
        when(attributeValueEidasResponse.getValue()).thenReturn("an eidas response string");
        when(stringtoOpenSamlObjectTransformer.apply("an eidas response string")).thenReturn(response);
        when(secretKeyDecryptorFactory.createDecrypter("an encrypted  key string")).thenReturn(decrypter);
        when(response.getEncryptedAssertions()).thenReturn(ImmutableList.of(encryptedAssertion));
        when(encryptedAssertion.getEncryptedData()).thenReturn(encryptedData);
        when(decrypter.decryptData(encryptedData)).thenReturn(eidasAssertion);

        MatchingDataset matchingDataset = unmarshaller.fromAssertion(unsignedAssertion);

        assertThat(matchingDataset).isNotNull();
        verify(firstNameValue).getFirstName();
        verify(personIdentifierValue).getPersonIdentifier();
        verify(stringtoOpenSamlObjectTransformer).apply("an eidas response string");
        verify(attributeValueEncryptionKeys).getValue();
        verify(attributeValueEidasResponse).getValue();
    }

}