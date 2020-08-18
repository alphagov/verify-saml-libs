package uk.gov.ida;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class Base64Test {

    private static final String STRING_PLAIN = "Ding dong, dingly dell, dibble dabble dooby.";
    private static final String STRING_BASE64 = "RGluZyBkb25nLCBkaW5nbHkgZGVsbCwgZGliYmxlIGRhYmJsZSBkb29ieS4=";

    private static final byte[] BYTES_PLAIN = STRING_PLAIN.getBytes();
    private static final byte[] BYTES_BASE64 = STRING_BASE64.getBytes();

    @Test
    public void shouldDecodeToByteArrayFromString() {
        assertThat(Base64.decodeToByteArray(STRING_BASE64)).isEqualTo(BYTES_PLAIN);
    }

    @Test
    public void shouldDecodeToByteArrayFromByteArray() {
        assertThat(Base64.decodeToByteArray(BYTES_BASE64)).isEqualTo(BYTES_PLAIN);
    }

    @Test
    public void shouldDecodeToStringFromString() {
        assertThat(Base64.decodeToString(STRING_BASE64)).isEqualTo(STRING_PLAIN);
    }

    @Test
    public void shouldDecodeToStringFromByteArray() {
        assertThat(Base64.decodeToString(BYTES_BASE64)).isEqualTo(STRING_PLAIN);
    }

    @Test
    public void shouldEncodeToByteArrayFromString() {
        assertThat(Base64.encodeToByteArray(STRING_PLAIN)).isEqualTo(BYTES_BASE64);
    }

    @Test
    public void shouldEncodeToByteArrayFromByteArray() {
        assertThat(Base64.encodeToByteArray(BYTES_PLAIN)).isEqualTo(BYTES_BASE64);
    }

    @Test
    public void shouldEncodeToStringFromString() {
        assertThat(Base64.encodeToString(STRING_PLAIN)).isEqualTo(STRING_BASE64);
    }

    @Test
    public void shouldEncodeToStringFromByteArray() {
        assertThat(Base64.encodeToString(BYTES_PLAIN)).isEqualTo(STRING_BASE64);
    }

/* MIME */

    @Test
    public void shouldMimeDecodeToByteArrayFromString() {
        assertThat(Base64.Mime.decodeToByteArray(STRING_BASE64)).isEqualTo(BYTES_PLAIN);
    }

    @Test
    public void shouldMimeDecodeToByteArrayFromByteArray() {
        assertThat(Base64.Mime.decodeToByteArray(BYTES_BASE64)).isEqualTo(BYTES_PLAIN);
    }

    @Test
    public void shouldMimeDecodeToStringFromString() {
        assertThat(Base64.Mime.decodeToString(STRING_BASE64)).isEqualTo(STRING_PLAIN);
    }

    @Test
    public void shouldMimeDecodeToStringFromByteArray() {
        assertThat(Base64.Mime.decodeToString(BYTES_BASE64)).isEqualTo(STRING_PLAIN);
    }

    @Test
    public void shouldMimeEncodeToByteArrayFromString() {
        assertThat(Base64.Mime.encodeToByteArray(STRING_PLAIN)).isEqualTo(BYTES_BASE64);
    }

    @Test
    public void shouldMimeEncodeToByteArrayFromByteArray() {
        assertThat(Base64.Mime.encodeToByteArray(BYTES_PLAIN)).isEqualTo(BYTES_BASE64);
    }

    @Test
    public void shouldMimeEncodeToStringFromString() {
        assertThat(Base64.Mime.encodeToString(STRING_PLAIN)).isEqualTo(STRING_BASE64);
    }

    @Test
    public void shouldMimeEncodeToStringFromByteArray() {
        assertThat(Base64.Mime.encodeToString(BYTES_PLAIN)).isEqualTo(STRING_BASE64);
    }
}