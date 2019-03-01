package uk.gov.ida.saml.core.transformers;

import com.google.common.collect.Lists;
import org.apache.commons.codec.binary.Hex;
import org.joda.time.DateTime;
import org.joda.time.LocalDate;
import org.opensaml.security.crypto.JCAConstants;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.MessageDigest;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class EidasResponseAttributesHashLogger {

    private Logger log = Logger.getLogger(getClass().getName());

    private transient final ResponseAttributes responseAttributes;

    private EidasResponseAttributesHashLogger() {
        responseAttributes = new ResponseAttributes();
    }

    public static EidasResponseAttributesHashLogger instance() {
        return new EidasResponseAttributesHashLogger();
    }

    public void setPid(String pid) {
        responseAttributes.setPid(pid);
    }

    public void setFirstName(String firstName) {
        responseAttributes.setFirstName(firstName);
    }

    public void addMiddleName(String middleName) {
        this.responseAttributes.addMiddleName(middleName);
    }

    public void addSurname(String surname) {
        this.responseAttributes.addSurName(surname);
    }

    public void setDateOfBirth(DateTime dateOfBirth) {
        this.responseAttributes.setDateOfBirth(dateOfBirth.toLocalDate());
    }

    public void logHashFor(Level level, String pid) {
        log.log(level, () -> String.format("Hash of eIDAS user attributes for pid '%s' is '%s'", pid, buildHash()));
    }

    protected String buildHash() {

        try (
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                ObjectOutputStream oos = new ObjectOutputStream(baos)
        ) {

            oos.writeObject(this.responseAttributes);
            MessageDigest md = MessageDigest.getInstance(JCAConstants.DIGEST_SHA256);
            return Hex.encodeHexString(md.digest(baos.toByteArray()));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private final static class ResponseAttributes implements Serializable {
        private String pid;
        private String firstName;
        private List<String> middleNames = Lists.newArrayList();
        private List<String> surnames = Lists.newArrayList();
        private LocalDate dateOfBirth;

        public void setPid(String pid) {
            this.pid = pid;
        }

        public void setFirstName(String firstName) {
            this.firstName = firstName;
        }

        public void addMiddleName(String middleName) {
            this.middleNames.add(middleName);
        }

        public void addSurName(String surname) {
            this.surnames.add(surname);
        }

        public void setDateOfBirth(LocalDate dateOfBirth) {
            this.dateOfBirth = dateOfBirth;
        }
    }
}
