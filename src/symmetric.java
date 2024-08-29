// Java program to generate
// a symmetric key

import com.sun.xml.internal.bind.v2.runtime.reflect.opt.Const;

import java.io.Serializable;
import java.lang.reflect.Array;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security
        .SecureRandom;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Random;
import java.lang.Object;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.print.DocFlavor;
import javax.xml.bind.DatatypeConverter;

public class symmetric {

    static GCMParameterSpec spec;
    static SecretKey SymmetricKey;
    private static final String key = "aesEncryptionKey";

    // Function to create a secret key
    public static SecretKey createAESKey(String password)
            throws Exception {

        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        KeySpec passwordBasedEncryptionKeySpec = new PBEKeySpec(password.toCharArray(), key.getBytes(), 12288, 128);
        SecretKey secretKeyFromPBKDF2 = secretKeyFactory.generateSecret(passwordBasedEncryptionKeySpec);
        SymmetricKey = new SecretKeySpec(secretKeyFromPBKDF2.getEncoded(), "AES");
        return SymmetricKey;
    }

    public static SecretKey  GenerateSessionKey() throws NoSuchAlgorithmException {
        KeyGenerator keygenerator = KeyGenerator.getInstance("AES");
        SymmetricKey= keygenerator.generateKey();

        return SymmetricKey;
    }





    public static GCMParameterSpec getGCMParameterSpec(byte[] nonce) {
        // final byte[] nonce = new byte[32];
        //random.nextBytes(nonce);

        GCMParameterSpec spec = new GCMParameterSpec(16 * 8, nonce);
        return spec;

    }



    public static byte[] MAC(ArrayList request) throws Exception {

        Mac mac = Mac.getInstance("HMACSHA1");
        mac.init(SymmetricKey);
        mac.update(request.toString().getBytes());
        byte[] macResult = mac.doFinal();

        //   System.out.println(java.util.Arrays.toString(mac.doFinal()));
        return macResult;
    }


    public static String encrypt(String data, GCMParameterSpec GCM) {
         String s = "";
        Cipher cipher = null;
        try {

            cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, SymmetricKey); // or Cipher.DECRYPT_MODE

            byte[] encrypted = cipher.doFinal(data.getBytes());
            s = Base64.getEncoder().encodeToString(encrypted);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }  catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
      return s;
    }

    public static String decrypt(String data, GCMParameterSpec GCM) {
        byte[] encrypted = Base64.getDecoder().decode(data);

        String s = "";
        Cipher cipher = null;
        try {

            cipher = Cipher.getInstance("AES");

            cipher.init(Cipher.DECRYPT_MODE, SymmetricKey);

            byte[] decrypted = cipher.doFinal(encrypted);
             s = new String(decrypted, StandardCharsets.UTF_8);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }  catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }


        return s;
    }



    public static void main(String args[])
            throws Exception {
        SecretKey Symmetrickey
                = GenerateSessionKey();
        System.out.println("Output");
        System.out.println("The Symmetric Key is :"
                + DatatypeConverter.printHexBinary(
                Symmetrickey.getEncoded()));


        SecureRandom random = SecureRandom.getInstanceStrong();
        final byte[] nonce = new byte[32];
        random.nextBytes(nonce);


        spec = getGCMParameterSpec(nonce);

        String b=encrypt("data",spec);

          System.out.println(b+decrypt(b,spec));

//        ArrayList x = new ArrayList();
//        x.add("getPass");
//        x.add("3");
//        MAC(x);
//        MAC(x);

    }
}
