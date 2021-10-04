package uk.gov.ida.saml.security.signature;

import io.prometheus.client.Counter;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialResolver;
import org.opensaml.security.credential.impl.StaticCredentialResolver;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import uk.gov.ida.saml.core.test.TestCertificateStrings;
import uk.gov.ida.saml.core.test.TestEntityIds;
import uk.gov.ida.saml.security.saml.OpenSAMLMockitoRunner;
import uk.gov.ida.saml.security.saml.TestCredentialFactory;
import uk.gov.ida.saml.security.saml.builders.AssertionBuilder;
import uk.gov.ida.saml.security.saml.builders.SignatureBuilder;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@RunWith(OpenSAMLMockitoRunner.class)
public class OutgoingKeySignatureTrustEngineTest {

    @Test
    public void shouldVerifyIdpWithAValidSigningCertificate() throws Exception {
        final Credential outgoingSigningCredential = new TestCredentialFactory(
                TestCertificateStrings.HUB_TEST_PUBLIC_SIGNING_CERT,
                TestCertificateStrings.HUB_TEST_PRIVATE_SIGNING_KEY
        ).getSigningCredential();
        final CredentialResolver credentialResolver = new StaticCredentialResolver(
                Collections.singletonList(outgoingSigningCredential)
        );
        final KeyInfoCredentialResolver keyInfoResolver = DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver();

        OutgoingKeySignatureTrustEngine trustEngine = new OutgoingKeySignatureTrustEngine(credentialResolver, keyInfoResolver);
        
        CriteriaSet trustBasisCriteria = new CriteriaSet();
        trustBasisCriteria.add(
                new EntityIdCriterion(TestEntityIds.HUB_ENTITY_ID)
        );
        
        Counter outgoingSignatureVerifyingErrorCounter = mock(Counter.class);
        setFinalStatic(OutgoingKeySignatureTrustEngine.class.getDeclaredField("outgoingSignatureVerifyingErrorCounter"), outgoingSignatureVerifyingErrorCounter);

        final Credential incomingSigningCredential = new TestCredentialFactory(TestCertificateStrings.HUB_TEST_PUBLIC_SIGNING_CERT, TestCertificateStrings.HUB_TEST_PRIVATE_SIGNING_KEY).getSigningCredential();
        final Assertion assertion = AssertionBuilder.anAssertion().withSignature(SignatureBuilder.aSignature().withSigningCredential(incomingSigningCredential).build()).build();

        assertThat(trustEngine.doValidate(assertion.getSignature(), trustBasisCriteria)).isTrue();
        verifyNoInteractions(outgoingSignatureVerifyingErrorCounter);
    }
    
    @Test
    public void shouldSendErrorCounterValidatingWithOutgoingSigningCertificate() throws Exception {
        final Credential incomingSigningCredential = new TestCredentialFactory(
                TestCertificateStrings.EXPIRED_SIGNING_PUBLIC_CERT,
                TestCertificateStrings.EXPIRED_SIGNING_PRIVATE_KEY
        ).getSigningCredential();
        final Credential outgoingSigningCredential = new TestCredentialFactory(
                TestCertificateStrings.HUB_TEST_PUBLIC_SIGNING_CERT,
                TestCertificateStrings.HUB_TEST_PRIVATE_SIGNING_KEY
        ).getSigningCredential();
        final CredentialResolver credentialResolver = new StaticCredentialResolver(
                Arrays.asList(incomingSigningCredential, outgoingSigningCredential)
        );
        final KeyInfoCredentialResolver keyInfoResolver = DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver();

        OutgoingKeySignatureTrustEngine trustEngine = new OutgoingKeySignatureTrustEngine(credentialResolver, keyInfoResolver);

        CriteriaSet trustBasisCriteria = new CriteriaSet();
        trustBasisCriteria.add(
                new EntityIdCriterion(TestEntityIds.HUB_ENTITY_ID)
        );
        
        Counter outgoingSignatureVerifyingErrorCounter = mock(Counter.class);
        Counter.Child childCounter = mock(Counter.Child.class);
        setFinalStatic(OutgoingKeySignatureTrustEngine.class.getDeclaredField("outgoingSignatureVerifyingErrorCounter"), outgoingSignatureVerifyingErrorCounter);

        final Assertion outgoing_assertion = AssertionBuilder.anAssertion().withSignature(SignatureBuilder.aSignature().withSigningCredential(outgoingSigningCredential).build()).build();
        
        when(outgoingSignatureVerifyingErrorCounter.labels(anyString())).thenReturn(childCounter);
        doNothing().when(childCounter).inc();
        
        assertThat(trustEngine.doValidate(outgoing_assertion.getSignature(), trustBasisCriteria)).isTrue();
        verify(outgoingSignatureVerifyingErrorCounter).labels("verification_failed");
        verify(childCounter).inc();
    }

    private static void setFinalStatic(Field field, Object newValue) throws Exception {
        field.setAccessible(true);
        Field modifiersField = Field.class.getDeclaredField("modifiers");
        modifiersField.setAccessible(true);
        modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);
        field.set(null, newValue);
    }
}
