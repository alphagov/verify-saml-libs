package uk.gov.ida.saml.core.transformers;

import org.apache.commons.codec.binary.Hex;
import org.opensaml.security.crypto.JCAConstants;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.MessageFormat;
import java.util.regex.Pattern;

public class ResponseAttributesHashFactory {

    private ResponseAttributesHashFactory() {
    }

    public static String hashResponseDetails(String pid, String firstName, String middlename, String lastName, String dateOfBirth) {

        Pattern dateFormat = Pattern.compile("\\d{4}-\\d{2}-\\d{2}");

        if (!dateFormat.matcher(dateOfBirth).matches()) {
            throw new RuntimeException("Date does not match format YYYY-MM-DD");
        }

        MessageDigest messageDigest;

        try {
            messageDigest = MessageDigest.getInstance(JCAConstants.DIGEST_SHA256);

            String toHash = MessageFormat.format("{0},{1},{2},{3},{4}",
                    pid, firstName, middlename, lastName, dateOfBirth);

            messageDigest.update(toHash.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        byte[] digest = messageDigest.digest();

        return Hex.encodeHexString(digest);
    }
}
