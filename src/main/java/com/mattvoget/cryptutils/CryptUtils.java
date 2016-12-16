package com.mattvoget.cryptutils;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class CryptUtils {

    private static final String ENCRYPTION_ALGORITHM = "AES";
    private SecretKeySpec secretKeySpec;

    public CryptUtils(String secretKey){
        this.secretKeySpec = new SecretKeySpec(DigestUtils.md5(secretKey),ENCRYPTION_ALGORITHM);
    }

    private Cipher getCipher(int mode) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(mode, secretKeySpec);
        return cipher;
    }

    public String encrypt(String stringToEncrypt) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
        return new String(Hex.encodeHex(getCipher(Cipher.ENCRYPT_MODE).doFinal(stringToEncrypt.getBytes())));
    }

    public String decrypt(String stringToDecrypt) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, DecoderException {
        return new String(getCipher(Cipher.DECRYPT_MODE).doFinal(Hex.decodeHex(stringToDecrypt.toCharArray())));
    }

}
