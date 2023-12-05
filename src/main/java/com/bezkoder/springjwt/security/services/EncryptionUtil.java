package com.bezkoder.springjwt.security.services;


import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class EncryptionUtil {

    private static final String KEY = "w3Hit4BEQK8p0gY9OR5pDYNREHSWHU1kmDb7VLSFh1w=";
    private static final String ALGORITHM = "AES";

    //encrypts the provided string SSN
    public static String encryptSSN(String data) throws Exception {

        byte[] decodedKey = Base64.getDecoder().decode(KEY);
        //specifies the AES algorithm and the key constants from above
        SecretKeySpec keySpec = new SecretKeySpec(decodedKey, ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM);

        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        byte[] encryptedSSN = cipher.doFinal(data.getBytes());

        return Base64.getEncoder().encodeToString(encryptedSSN);
    }

    //decrypts the encrypted string SSN
    public static String decryptSSN(String encryptedData) throws Exception {

        //specifies the AES algorithm and the key constants from above
        byte[] decodedKey = Base64.getDecoder().decode(KEY);
        SecretKeySpec keySpec = new SecretKeySpec(decodedKey, ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        //preparee the cipher to decrypt instead of encrypt
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] ssn = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(ssn);
    }
}
