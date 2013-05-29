package test;

import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.*;
import javax.crypto.spec.*;

import org.apache.commons.codec.binary.Base64;

class Encryption {
    static String encode(String target) throws UnsupportedEncodingException, BadPaddingException,
            IllegalBlockSizeException, InvalidKeySpecException, InvalidKeyException, NoSuchAlgorithmException,
            NoSuchPaddingException {
        Cipher cipher = getCipher(Cipher.ENCRYPT_MODE);
        return encodeBase64(cipher.doFinal(target.getBytes("UTF-8")));
    }

    static String decode(String target) throws InvalidKeySpecException, InvalidKeyException,
            NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = getCipher(Cipher.DECRYPT_MODE);
        return new String(cipher.doFinal(decodeBase64(target)));
    }

    static String encodeBase64(byte[] target) {
        return new String(Base64.encodeBase64(target));
    }

    static byte[] decodeBase64(String target) {
        return Base64.decodeBase64(target.getBytes());
    }

    private static Cipher getCipher(int mode) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeySpecException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("Blowfish");
        SecretKeySpec keySpec = new SecretKeySpec(getPassword(), "Blowfish");
        cipher.init(mode, keySpec);
        return cipher;
    }

    private static byte[] getPassword() {
        return "secret".getBytes();
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 0) {
            System.out.println(encode(args[0]));
        }
    }
}
