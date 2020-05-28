import javax.crypto.*;
import java.io.*;
import java.security.*;



public class AsymmetricEncryption {

  /**
   * Generates a RSA public and private key pair.
   *
   * @return KeyPair object which is a simple holder for the PublicKey and
   * PrivateKey objects.
   */
  public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);
    KeyPair keyPair = keyGen.generateKeyPair();
    return keyPair;
  }

 /**
  * Encrypts plain text using the RSA/ECB/PKCS1Padding algorithm specification.
  *
  * @param plainText byte array to be encrypted
  * @param key key object that inherits the Key interface in the java.security
  * package. Generally the key argument will be of type PublicKey or PrivateKey
  * @return byte array that is the encrypted plain text
  */
  public static byte[] encrypt(byte[] plainText, Key key) throws Exception {
    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    // System.out.println(cipher.getProvider().getInfo()); // TODO rather log
    cipher.init(Cipher.ENCRYPT_MODE, key);
    byte[] cipherText = cipher.doFinal(plainText);
    return cipherText;
  }

  /**
   * Decrypts cipher text using the RSA/ECB/PKCS1Padding algorithm specification.
   *
   * @param cipherText byte array to be decrypted
   * @param key key object that inherits the Key interface in the java.security
   * package. Generally the key argument will be of type PublicKey or PrivateKey
   * @return byte array that is the decrypted cipher text
   */
  public static byte[] decrypt(byte[] cipherText, Key key) throws Exception {
    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    // System.out.println(cipher.getProvider().getInfo()); // TODO rather log
    cipher.init(Cipher.DECRYPT_MODE, key);
    byte[] plainText = cipher.doFinal(cipherText);
    return plainText;
  }

  public static void loadJKS(String filePath, String alias, String password) throws Exception {
    KeyStore keyStore = KeyStore.getInstance("JKS");
    keyStore.load(new FileInputStream(filePath), password.toCharArray());
    return keyStore;

  }

  public static void main(String[] args) {
    try {
      String msg = "whatup fuckers!!!!!";
      byte[] plainText = msg.getBytes();
      KeyPair keyPair = generateRSAKeyPair();

      PublicKey publicKey = keyPair.getPublic();
      byte[] cipherText = encrypt(plainText, publicKey);
      System.out.println(cipherText);

      PrivateKey privateKey = keyPair.getPrivate();
      byte[] newPlainText = decrypt(cipherText, privateKey);
      String newMsg = new String(newPlainText);
      System.out.println(newMsg);

      loadJKS("keystore.jks", "alice", "password123");


    } catch (NoSuchAlgorithmException e) {
      System.out.println("Error suckers!");
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}
