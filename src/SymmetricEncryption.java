import java.util.Arrays;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;


/**
* The class is a utility class for AES symmetric encryption.
*
* It contains all the relevant functionality needed for the creation of a
* symmetric session key that can be used to encrypt and decrypt messages in a
* client communication.
*/
public class SymmetricEncryption extends Encryption {
  private static final ClientLogger logger = new ClientLogger();
  private static final int IVLength = 128/8; // IV length must be 16 bytes for AES
  private static final String encryptionSpec = "AES";
  private static final int keyLength = 128;
  private static final String algSpec = "AES/CBC/PKCS5Padding";


  /**
  * Generates a initialisation vector for AES encryption.
  *
  * Every IV should only be used once. The IV accompanies the encrypted message
  * that is sent to the recipient
  *
  * @return byte array containing random bytes
  */
  public static byte[] generateIV() {
    SecureRandom random = new SecureRandom();
    byte[] ivBytes = new byte[IVLength]; // IV length must be 16 bytes long for AES
    random.nextBytes(ivBytes);
    IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
    return ivBytes;
  }


  /**
  * Generates an AES key.
  *
  * @return SecretKey object
  */
  public static SecretKey generateSecretKey() throws Exception {
    KeyGenerator keyGen = KeyGenerator.getInstance(encryptionSpec);
    keyGen.init(keyLength);
    SecretKey secretKey = keyGen.generateKey();
    return secretKey;
  }


  /**
  * Encrypts plain text using the AES/CBC/PKCS5Padding algorithm specification.
  *
  * @param plainText byte array to be encrypted
  * @param key Key object
  * @return byte array containing the encrypted plain text
  */
  public static byte[] encrypt(byte[] plainText, Key key, byte[] ivBytes) throws Exception {
    IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
    Cipher cipher = Cipher.getInstance(algSpec);
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    byte[] cipherText = cipher.doFinal(plainText);
    logger.logEncryption(algSpec, cipher, cipherText);
    return cipherText;
  }


  /**
  * Decrypts cipher text using the AES/CBC/PKCS5Padding algorithm specification.
  *
  * @param cipherText byte array to be decrypted
  * @param key Key object
  * @return byte array containing decrypted cipher text
  */
  public static byte[] decrypt(byte[] cipherText, Key key, byte[] ivBytes) throws Exception {
    IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
    Cipher cipher = Cipher.getInstance(algSpec);
    cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
    byte[] plainText = cipher.doFinal(cipherText);
    return plainText;
  }
}
