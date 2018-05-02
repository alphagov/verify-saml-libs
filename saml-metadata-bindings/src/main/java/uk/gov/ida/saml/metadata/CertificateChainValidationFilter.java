package uk.gov.ida.saml.metadata;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.metadata.resolver.filter.MetadataFilter;
import org.opensaml.saml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.ida.common.shared.security.verification.CertificateChainValidator;
import uk.gov.ida.saml.metadata.exception.CertificateConversionException;
import uk.gov.ida.saml.metadata.exception.EntityDescriptorListEmptyException;
import uk.gov.ida.saml.metadata.exception.KeyDescriptorListEmptyException;
import uk.gov.ida.saml.metadata.exception.RoleDescriptorListEmptyException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.validation.constraints.NotNull;
import javax.xml.namespace.QName;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static org.opensaml.xmlsec.keyinfo.KeyInfoSupport.getCertificates;

public final class CertificateChainValidationFilter implements MetadataFilter {

    private static final Logger LOG = LoggerFactory.getLogger(CertificateChainValidationFilter.class);

    private final QName role;
    private final CertificateChainValidator certificateChainValidator;
    private final KeyStore keyStore;

    public CertificateChainValidationFilter(
        @NotNull final QName role,
        @NotNull final CertificateChainValidator certificateChainValidator,
        @NotNull final KeyStore keyStore) {

        this.role = role;
        this.certificateChainValidator = certificateChainValidator;
        this.keyStore = keyStore;
    }

    public QName getRole() {
        return role;
    }

    public CertificateChainValidator getCertificateChainValidator() {
        return certificateChainValidator;
    }

    private KeyStore getKeyStore() {
        return keyStore;
    }

    @Nullable
    @Override
    public XMLObject filter(@Nullable final XMLObject metadata) {
        if (metadata == null) {
            return null;
        }

        try {
            if (metadata instanceof EntityDescriptor) {
                return getValidatedEntityDescriptor((EntityDescriptor) metadata);
            } else if (metadata instanceof EntitiesDescriptor) {
                return getValidatedEntitiesDescriptor((EntitiesDescriptor) metadata);
            } else {
                LOG.error("Internal error, metadata object was of an unsupported type: {}", metadata.getClass().getName());
                return null;
            }
        } catch (RoleDescriptorListEmptyException | EntityDescriptorListEmptyException | CertificateConversionException | MarshallingException | UnmarshallingException e) {
            LOG.error("Saw fatal error validating certificate chain, metadata will be filtered out", e);
            return null;
        }
    }

    private EntitiesDescriptor getValidatedEntitiesDescriptor(@Nonnull final EntitiesDescriptor entitiesDescriptor) throws EntityDescriptorListEmptyException, MarshallingException, UnmarshallingException {
        final String name = getGroupName(entitiesDescriptor);
        LOG.trace("Processing EntitiesDescriptor group: {}", name);

        ArrayList<EntityDescriptor> validatedEntityDescriptors = new ArrayList<>();
        for (final EntityDescriptor entityDescriptor : entitiesDescriptor.getEntityDescriptors()) {
            try {
                validatedEntityDescriptors.add(getValidatedEntityDescriptor(entityDescriptor));
            } catch (final RoleDescriptorListEmptyException e) {
                LOG.warn("EntityDescriptor '{}' has empty validated role descriptor list, removing from metadata provider", entityDescriptor.getEntityID());
            }
        }

        if (validatedEntityDescriptors.isEmpty()) {
            throw new EntityDescriptorListEmptyException("Validated entity descriptor list is empty");
        }

        EntitiesDescriptor validatedEntitiesDescriptor = XMLObjectSupport.cloneXMLObject(entitiesDescriptor);
        validatedEntitiesDescriptor.getEntityDescriptors().clear();
        validatedEntitiesDescriptor.getEntityDescriptors().addAll(validatedEntityDescriptors);
        return validatedEntitiesDescriptor;
    }

    private EntityDescriptor getValidatedEntityDescriptor(@Nonnull final EntityDescriptor entityDescriptor) throws RoleDescriptorListEmptyException, MarshallingException, UnmarshallingException {
        final String entityID = entityDescriptor.getEntityID();
        LOG.trace("Validating EntityDescriptor: {}", entityID);

        ArrayList<RoleDescriptor> validatedRoleDescriptors = new ArrayList<>();

        for (final RoleDescriptor roleDescriptor : entityDescriptor.getRoleDescriptors()) {
            if (getRole().equals(roleDescriptor.getElementQName())) {
                if (SPSSODescriptor.DEFAULT_ELEMENT_NAME.equals(roleDescriptor.getElementQName())) {
                    try {
                        SPSSODescriptor spssoDescriptor = XMLObjectSupport.cloneXMLObject((SPSSODescriptor) roleDescriptor);
                        spssoDescriptor.getKeyDescriptors().clear();
                        spssoDescriptor.getKeyDescriptors().addAll(getValidatedKeyDescriptors(roleDescriptor));
                        validatedRoleDescriptors.add(spssoDescriptor);
                    } catch (final KeyDescriptorListEmptyException e) {
                        LOG.warn("SPSSODescriptor '{}' has empty validated key descriptor list, removing from metadata provider", entityDescriptor.getEntityID());
                    }
                } else if (IDPSSODescriptor.DEFAULT_ELEMENT_NAME.equals(roleDescriptor.getElementQName())) {
                    try {
                        IDPSSODescriptor idpssoDescriptor = XMLObjectSupport.cloneXMLObject((IDPSSODescriptor) roleDescriptor);
                        idpssoDescriptor.getKeyDescriptors().clear();
                        idpssoDescriptor.getKeyDescriptors().addAll(getValidatedKeyDescriptors(roleDescriptor));
                        validatedRoleDescriptors.add(idpssoDescriptor);
                    } catch (final KeyDescriptorListEmptyException e) {
                        LOG.warn("IDPSSODescriptor '{}' has empty validated key descriptor list, removing from metadata provider", entityDescriptor.getEntityID());
                    }
                }
            } else {
                validatedRoleDescriptors.add(XMLObjectSupport.cloneXMLObject(roleDescriptor));
            }
        }

        if (validatedRoleDescriptors.isEmpty()) {
            throw new RoleDescriptorListEmptyException("Validated role descriptor list is empty");
        }

        EntityDescriptor validatedEntityDescriptor = XMLObjectSupport.cloneXMLObject(entityDescriptor);
        validatedEntityDescriptor.getRoleDescriptors().clear();
        validatedEntityDescriptor.getRoleDescriptors().addAll(validatedRoleDescriptors);

        return validatedEntityDescriptor;
    }

    private List<KeyDescriptor> getValidatedKeyDescriptors(@Nonnull final RoleDescriptor roleDescriptor) throws KeyDescriptorListEmptyException, MarshallingException, UnmarshallingException {
        ArrayList<KeyDescriptor> validatedKeyDescriptors = new ArrayList<>();
        boolean validCertificate;

        for (final KeyDescriptor keyDescriptor : roleDescriptor.getKeyDescriptors()) {
            validCertificate = true;
            final KeyInfo keyInfo = keyDescriptor.getKeyInfo();
            try {
                for (final X509Certificate certificate : getCertificates(keyInfo)) {
                    if (!getCertificateChainValidator().validate(certificate, getKeyStore()).isValid()) {
                        LOG.error("Certificate chain validation failed for metadata entry {}", certificate.getSubjectDN());
                        validCertificate = false;
                    }
                }
            } catch (final CertificateException e) {
                throw new CertificateConversionException(e);
            }
            if (validCertificate) {
                validatedKeyDescriptors.add(XMLObjectSupport.cloneXMLObject(keyDescriptor));
            }
        }

        if (validatedKeyDescriptors.isEmpty()) {
            throw new KeyDescriptorListEmptyException("Validated key descriptor list is empty");
        }

        return validatedKeyDescriptors;
    }

    private String getGroupName(final EntitiesDescriptor group) {
        String name = group.getName();
        if (name != null) {
            return name;
        }
        name = group.getID();
        if (name != null) {
            return name;
        }
        return "(unnamed)";
    }
}
