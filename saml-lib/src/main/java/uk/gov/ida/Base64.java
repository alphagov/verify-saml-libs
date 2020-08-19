package uk.gov.ida;

public class Base64 {
    public static byte[] decodeToByteArray(String base64) {
        return java.util.Base64.getDecoder().decode(base64);
    }

    public static byte[]  decodeToByteArray(byte[] base64) {
        return java.util.Base64.getDecoder().decode(base64);
    }

    public static String decodeToString(String base64) {
        return new String(java.util.Base64.getDecoder().decode(base64));
    }

    public static String decodeToString(byte[] base64) {
        return new String(java.util.Base64.getDecoder().decode(base64));
    }

    public static byte[] encodeToByteArray(String plain) {
        return java.util.Base64.getEncoder().encode(plain.getBytes());
    }

    public static byte[] encodeToByteArray(byte[] plain) {
        return java.util.Base64.getEncoder().encode(plain);
    }

    public static String encodeToString(String plain) {
        return new String(java.util.Base64.getEncoder().encode(plain.getBytes()));
    }

    public static String encodeToString(byte[] plain) {
        return new String(java.util.Base64.getEncoder().encode(plain));
    }

    public static class Mime {
        public static byte[] decodeToByteArray(String base64) {
            return java.util.Base64.getMimeDecoder().decode(base64);
        }

        public static byte[]  decodeToByteArray(byte[] base64) {
            return java.util.Base64.getMimeDecoder().decode(base64);
        }

        public static String decodeToString(String base64) {
            return new String(java.util.Base64.getMimeDecoder().decode(base64));
        }

        public static String decodeToString(byte[] base64) {
            return new String(java.util.Base64.getMimeDecoder().decode(base64));
        }

        public static byte[] encodeToByteArray(String plain) {
            return java.util.Base64.getMimeEncoder().encode(plain.getBytes());
        }

        public static byte[] encodeToByteArray(byte[] plain) {
            return java.util.Base64.getMimeEncoder().encode(plain);
        }

        public static String encodeToString(String plain) {
            return new String(java.util.Base64.getMimeEncoder().encode(plain.getBytes()));
        }

        public static String encodeToString(byte[] plain) {
            return new String(java.util.Base64.getMimeEncoder().encode(plain));
        }
    }
}
