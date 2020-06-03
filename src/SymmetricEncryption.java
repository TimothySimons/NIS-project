import java.util.Arrays;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

public class SymmetricEncryption {

  public static byte[] generateIV() {
    SecureRandom random = new SecureRandom();
    byte[] ivBytes = new byte[128/8]; // IV length must be 16 bytes long for AES
    random.nextBytes(ivBytes);
    IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
    return ivBytes;
  }


  /**
  * Generates an AES key.
  *
  * @return SecretKey object
  */
  public static SecretKey generateSecretAESKey() throws Exception {
    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    keyGen.init(256);
    SecretKey secretKey = keyGen.generateKey();
    return secretKey;
  }

  /**
  * Encrypts plain text using the AES/CBC/PKCS5Padding algorithm specification.
  *
  * @param plainText byte array to be encrypted
  * @param key Key object
  * @return byte array that is the encrypted plain text
  */
  public static byte[] encrypt(byte[] plainText, Key key, byte[] ivBytes) throws Exception {
    IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    byte[] cipherText = cipher.doFinal(plainText);
    return cipherText;
  }


  /**
  * Decrypts cipher text using the AES/CBC/PKCS5Padding algorithm specification.
  *
  * @param cipherText byte array to be decrypted
  * @param key Key object
  * @return byte array that is the decrypted cipher text
  */
  public static byte[] decrypt(byte[] cipherText, Key key, byte[] ivBytes) throws Exception {
    IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
    byte[] plainText = cipher.doFinal(cipherText);
    return plainText;
  }

  // TODO: Compression of secret msg


}
