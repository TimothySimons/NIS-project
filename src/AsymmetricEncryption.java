import javax.crypto.*;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import java.util.zip.*;
import javax.security.auth.x500.X500Principal;
import javax.security.sasl.AuthenticationException;
// TODO: spefify all imports (as is best practice)



public class AsymmetricEncryption {

  /**
  * Generates a RSA public and private key pair.
  *
  * This is currently only used for debuging purposes as the public and private
  * keys are kept in java key stores.
  *
  * @return KeyPair object which is a simple holder for the PublicKey and
  * PrivateKey objects.
  */
  public static KeyPair generateRSAKeyPair() throws Exception {
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
    * package. The key argument will be of type PublicKey or PrivateKey
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
  * package. The key argument will be of type PublicKey or PrivateKey
  * @return byte array that is the decrypted cipher text
  */
  public static byte[] decrypt(byte[] cipherText, Key key) throws Exception {
    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    // System.out.println(cipher.getProvider().getInfo()); // TODO rather log
    cipher.init(Cipher.DECRYPT_MODE, key);
    byte[] plainText = cipher.doFinal(cipherText);
    return plainText;
  }


  /**
  * Loads a KeyStore object for a client.
  *
  * A KeyStore consists of a database containing a private key and an associated
  * certificate, or an associated certificate chain. The certificate chain
  * consists of the client certificate and one or more certification authority
  * (CA) certificates.
  *
  * @param JSKFilePath path to a Java Key Store (JKS)
  * @param alias alias of certificate in the JKS
  * @return key store containing keys and certificates.
  */
  public static KeyStore loadJKS(String JKSFilePath, String alias, String password) throws Exception {
    KeyStore keyStore = KeyStore.getInstance("JKS");
    keyStore.load(new FileInputStream(JKSFilePath), password.toCharArray());
    return keyStore;
  }


  /**
  * Authenticates the identity of the principle that the certificate represents.
  * In other words, it authenticates that the private key corresponding to the
  * public key in the certificate is owned by the certificate's subject.
  *
  * @param JSKFilePath path to the local host's Java Key Store (JKS)
  * @param password password to access the specified JKS
  * @param rootCertAlias alias of the root certificate in the JKS
  * @param cert certificate to be authenticated
  */
  public static void authenticateCert(KeyStore keyStore, String password, X509Certificate CARootCert, X509Certificate cert)
  throws Exception
  {
    cert.checkValidity();
    PublicKey CARootCertPublicKey = CARootCert.getPublicKey();
    cert.verify(CARootCertPublicKey);
  }


/**
 * Creates a message to authenticate to the remote client that the local client
 * owns the private key corresponding to the public key in the sent certificate.
 *
 * @param randDataLength the length of the random message to be used in the
 * authentication message.
 * @param privateKey private key of the local client to sign the message digest
 */
  public static byte[] createAuthMsg(int randDataLength, PrivateKey privateKey) throws Exception {
    // random data
    SecureRandom random = new SecureRandom();
    byte[] randomData = new byte[randDataLength];
    random.nextBytes(randomData);

    // hashed and signed
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.update(randomData);
    byte[] digest = md.digest();
    byte[] signedDigest = AsymmetricEncryption.encrypt(digest, privateKey);
    System.out.println("Random data: " + randomData.length);
    System.out.println("Signed digest: " + signedDigest.length);

    // concatenate signed digest with original message
    ByteArrayOutputStream baosConcat = new ByteArrayOutputStream();
    baosConcat.write(signedDigest);
    baosConcat.write(randomData);
    byte[] concatMsg = baosConcat.toByteArray();

    // compression
    Deflater compresser = new Deflater();
    compresser.setInput(concatMsg);
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream(concatMsg.length);
    compresser.finish();
    byte[] buffer = new byte[1024];
    while(!compresser.finished()) {
      int count = compresser.deflate(buffer);
      outputStream.write(buffer, 0, count);
    }
    outputStream.close();
    byte[] authMsg = outputStream.toByteArray();
    System.out.println("Original: " + concatMsg.length);
    System.out.println("Compressed: " + authMsg.length);
    return authMsg;
  }

  /**
   * Verifies that a remote client owns the private key corresponding to a
   * known public key.
   *
   * @param authMsg the message sent by the remote client for authentication
   * @param privateKey public key of the local client that was taken from the
   * certificate sent by the client
   */
  public static void verifyAuthMsg(byte[] authMsg, PublicKey publicKey) throws Exception {
    // decompression
    Inflater decompresser = new Inflater();
    decompresser.setInput(authMsg);
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream(authMsg.length);
    byte[] buffer = new byte[1024];
    while(!decompresser.finished()) {
      int count = decompresser.inflate(buffer);
      outputStream.write(buffer, 0, count);
    }
    outputStream.close();
    byte[] concatMsg = outputStream.toByteArray();
    System.out.println("Original: " + concatMsg.length);
    System.out.println("Compressed: " + authMsg.length);

    // split
    byte[] signedDigest = Arrays.copyOfRange(concatMsg, 0, 256); // TODO: may not be 256 bits
    byte[] randomData = Arrays.copyOfRange(concatMsg, 256, concatMsg.length);

    // verify
    byte[] digest = AsymmetricEncryption.decrypt(signedDigest, publicKey);
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.update(randomData);
    byte[] hash = md.digest();
    if (!MessageDigest.isEqual(digest, hash)) {
      throw new AuthenticationException();
    }
  }
}
