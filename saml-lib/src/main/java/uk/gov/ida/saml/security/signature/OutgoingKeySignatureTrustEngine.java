package uk.gov.ida.saml.security.signature;

import com.google.common.base.Strings;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialResolver;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.criteria.KeyAlgorithmCriterion;
import org.opensaml.security.criteria.UsageCriterion;
import org.opensaml.xmlsec.algorithm.AlgorithmSupport;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import io.prometheus.client.Counter;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class OutgoingKeySignatureTrustEngine extends ExplicitKeySignatureTrustEngine {
    /**
     * Constructor.
     *
     * @param resolver        credential resolver used to resolve trusted credentials.
     * @param keyInfoResolver KeyInfo credential resolver used to obtain the (advisory) signing credential from a 
     *                        trusted credential store
     */
    private final Logger log = LoggerFactory.getLogger(OutgoingKeySignatureTrustEngine.class);
    private static Counter outgoingSignatureVerifyingErrorCounter = Counter.build(
                    "verify_saml_lib_signature_verifying_error_counter",
                    "Counter to detect errors on the outgoing signature, reports the number of errors")
            .labelNames("error_type")
            .register();

    public OutgoingKeySignatureTrustEngine(@Nonnull CredentialResolver resolver, @Nonnull KeyInfoCredentialResolver keyInfoResolver) {
        super(resolver, keyInfoResolver);
    }

    @Override
    protected boolean doValidate(@Nonnull final Signature signature,
                                 @Nullable final CriteriaSet trustBasisCriteria) throws SecurityException {

        final CriteriaSet criteriaSet = new CriteriaSet();
        criteriaSet.addAll(trustBasisCriteria);
        if (!criteriaSet.contains(UsageCriterion.class)) {
            criteriaSet.add(new UsageCriterion(UsageType.SIGNING));
        }
        final String jcaAlgorithm = AlgorithmSupport.getKeyAlgorithm(signature.getSignatureAlgorithm());
        if (!Strings.isNullOrEmpty(jcaAlgorithm)) {
            criteriaSet.add(new KeyAlgorithmCriterion(jcaAlgorithm), true);
        }

        final Iterable<Credential> trustedCredentials;
        try {
            trustedCredentials = getCredentialResolver().resolve(criteriaSet);
        } catch (final ResolverException e) {
            throw new SecurityException("Error resolving trusted credentials", e);
        }

        if (validate(signature, trustedCredentials)) {
            return true;
        }

        // If the credentials extracted from Signature's KeyInfo (if any) did not verify the
        // signature and/or establish trust, as a fall back attempt verify the signature with
        // the trusted credentials directly.
        log.debug("Attempting to verify signature using trusted credentials");

        for (final Credential trustedCredential : trustedCredentials) {
            if (verifySignature(signature, trustedCredential)) {
                log.debug("Successfully verified signature using resolved trusted credential");
                return true;
            }
            outgoingSignatureVerifyingErrorCounter.labels("verification_failed").inc();
            log.warn("Failed to verify signature using trusted credentials");
        }
        log.debug("Failed to verify signature using either KeyInfo-derived or directly trusted credentials");
        return false;
    }
}
