import javax.crypto.Cipher;
import java.security.*;

public class Hyper {
    private static final String RSA = "RSA";

    public static KeyPair generateKeyPair()
            throws Exception
    {
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
        keyPairGenerator.initialize(2048, secureRandom);
        return keyPairGenerator.generateKeyPair();
    }

    // Encryption function which converts
    public static byte[] Encrept(String plainText, PublicKey publicKey)
            throws Exception
    {
        Cipher cipher = Cipher.getInstance(RSA);

        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return cipher.doFinal(plainText.getBytes());
    }

    // Decryption function
    public static String Decrept(String cipherText, PrivateKey privateKey)
            throws Exception
    {
        byte[] messageToBytes = cipherText.getBytes();
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] result = cipher.doFinal(messageToBytes);

        return new String(result);
    }

    public static String Decreptsecretkeyserver(byte[] cipherText, PrivateKey privateKey)
            throws Exception
    {
        Cipher cipher = Cipher.getInstance(RSA);

        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] result = cipher.doFinal(cipherText);

        return new String(result);
    }
    // Decryption function
    public static String Decrept2(byte[] cipherText, PrivateKey privateKey)
            throws Exception
    {
        Cipher cipher
                = Cipher.getInstance(RSA);

        cipher.init(Cipher.DECRYPT_MODE,
                privateKey);
        byte[] result
                = cipher.doFinal(cipherText);

        return new String(result);
    }
}
