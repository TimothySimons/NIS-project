import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.cert.Certificate;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.net.ServerSocketFactory;
import javax.security.sasl.AuthenticationException;
import javax.net.ssl.*;

// TODO: make key message sizes, algorithms etc constant.
// TODO: add compression and hashing to the secret message communication.
// TODO: add testing and debuging

public class Client {
  private final ClientLogger logger = new ClientLogger();
  private final int randomDataLength = 2048;
  private final String encryptionSpec = "AES";
  private final String hashAlg = "SHA-256";
  private final int msgDigestLength = 32; // 32 bytes or 256 bits
  private String alias;
  private String password;
  private KeyStore keyStore;
  private PrivateKey privateKey;
  private PublicKey publicKey;
  private X509Certificate cert;
  private X509Certificate CARootCert;

  public Client(String JKSFilePath, String alias, String password, String CARootAlias) throws Exception {
    this.alias = alias;
    this.password = password;
    this.keyStore = AsymmetricEncryption.loadJKS(JKSFilePath, alias, password);
    this.privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
    this.cert = (X509Certificate) keyStore.getCertificate(alias);
    this.publicKey = cert.getPublicKey();
    this.CARootCert = (X509Certificate) keyStore.getCertificate(CARootAlias);
  }

 /**
  * Encapsulates the communication between two clients from the listening client's
  * perspective.
  *
  */
  public void listeningClientActions(int portNumber) throws Exception {
    // connection
    Socket socket = listen(portNumber);
    logger.logConnection(socket);

    // certificate verification
    sendCert(socket);
    X509Certificate remoteCert = receiveCert(socket);
    AsymmetricEncryption.authenticateCert(this.keyStore, this.password, this.CARootCert, remoteCert);

    // client authentication
    byte[] authMsgOut = AsymmetricEncryption.createAuthMsg(this.randomDataLength, this.privateKey);
    sendBytes(socket, authMsgOut);
    byte[] authMsgIn = receiveBytes(socket);
    logger.logMsg("Received authentication message from connected client\n");
    PublicKey remotePublicKey = remoteCert.getPublicKey();
    AsymmetricEncryption.verifyAuthMsg(authMsgIn, remotePublicKey);

    // shared-key session
    SecretKey secretKey = SymmetricEncryption.generateSecretKey();
    byte[] encodedSecretKey = secretKey.getEncoded();
    byte[] encryptedSecretKey = AsymmetricEncryption.encrypt(encodedSecretKey, remotePublicKey);
    sendBytes(socket, encryptedSecretKey);

    // encrypted secret message and message digest
    byte[] ivBytes = receiveBytes(socket);
    logger.logMsg("Received one-time initalisation vector from connected client\n");
    byte[] compressedBytes = receiveBytes(socket);
    byte[] encryptedBytes = SymmetricEncryption.decompress(compressedBytes);
    logger.logMsg("Received confidential message from connected client\n");
    byte[] concatMsg = SymmetricEncryption.decrypt(encryptedBytes, secretKey, ivBytes);
    byte[] decryptedHash = Arrays.copyOfRange(concatMsg, 0, this.msgDigestLength);
    byte[] secretMsgBytes = Arrays.copyOfRange(concatMsg, this.msgDigestLength, concatMsg.length);
    String secretMsg = new String(secretMsgBytes);
    logger.logMsg("Decrypted secret message:\n" + secretMsg);

    // secret message integrity
    byte[] hash = SymmetricEncryption.computeHash(secretMsgBytes, hashAlg);
    if (!MessageDigest.isEqual(decryptedHash, hash)) {
      throw new AuthenticationException();
    }
  }


  public void connectingClientActions(String hostName, int portNumber, String secretMsg) throws Exception {
    // connection
    Socket socket = connect(hostName, portNumber);
    logger.logConnection(socket);

    // certificate verification
    X509Certificate remoteCert = receiveCert(socket);
    AsymmetricEncryption.authenticateCert(this.keyStore, this.password, this.CARootCert, remoteCert);
    sendCert(socket);

    // client authentication
    byte[] authMsgIn = receiveBytes(socket);
    logger.logMsg("Received authentication message from connected client\n");
    PublicKey remotePublicKey = remoteCert.getPublicKey();
    AsymmetricEncryption.verifyAuthMsg(authMsgIn, remotePublicKey);
    byte[] authMsgOut = AsymmetricEncryption.createAuthMsg(this.randomDataLength, this.privateKey);
    sendBytes(socket, authMsgOut);

    // shared-key session
    byte[] encryptedSecretKey = receiveBytes(socket);
    logger.logMsg("Received encrypted session key from connected client\n");
    byte[] encodedSecretKey = AsymmetricEncryption.decrypt(encryptedSecretKey, this.privateKey);
    byte[] ivBytes = SymmetricEncryption.generateIV();
    SecretKeySpec secretKey = new SecretKeySpec(encodedSecretKey, this.encryptionSpec);

    // encrypted secret and message digest
    byte[] secretMsgBytes = secretMsg.getBytes();
    byte[] hash = SymmetricEncryption.computeHash(secretMsgBytes, this.hashAlg);
    ByteArrayOutputStream baosConcat = new ByteArrayOutputStream();
    baosConcat.write(hash);
    baosConcat.write(secretMsgBytes);
    byte[] concatMsg = baosConcat.toByteArray();

    byte[] encryptedBytes = SymmetricEncryption.encrypt(concatMsg, secretKey, ivBytes);
    byte[] compressedBytes = SymmetricEncryption.compress(encryptedBytes);
    sendBytes(socket, ivBytes);
    sendBytes(socket, compressedBytes);
  }


  /**
   * Listens for a connection and returns the associated socket.
   *
   * @param portNumber local port number on which to listen for a connection
   * @return socket associated with the connected client
   */
  private Socket listen(int portNumber) throws IOException {
      ServerSocket serverSocket = new ServerSocket(portNumber);
      Socket socket = serverSocket.accept();
      return socket;
  }


  /**
   * Attempts to connect to the listening client.
   *
   * @param hostName the name of the remote host
   * @param portNumber the port number on which the remote host is listening
   * @return socket associated with the connected client
   */
  private Socket connect(String hostName, int portNumber)
  throws UnknownHostException, IOException {
      Socket socket = new Socket(hostName, portNumber);
      return socket;
  }


/**
 * Sends a Certificate object across a network to the remote host.
 *
 * @param socket endpoint for the communication to the remote host
 * @param cert the signed certificate of the local host
 */
  private void sendCert(Socket socket)
  throws SocketException, IOException {
      ObjectOutputStream outputStream = new ObjectOutputStream(socket.getOutputStream());
      outputStream.writeObject(this.cert);
  }


  /**
   * Receive a Certificate object from the remote host.
   *
   * @param socket endpoint for the communication to the remote host
   * @return signed certificate of the remote host
   */
  private X509Certificate receiveCert(Socket socket)
  throws SocketException, IOException, ClassNotFoundException {
      ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream());
      X509Certificate cert = (X509Certificate) inStream.readObject();
      logger.logRemoteCert(cert);
      return cert;
  }


  private void sendBytes(Socket socket, byte[] authMsg)
  throws SocketException, IOException {
    DataOutputStream outStream = new DataOutputStream(socket.getOutputStream());
    outStream.writeInt(authMsg.length);
    outStream.write(authMsg);
  }


  private byte[] receiveBytes(Socket socket)
  throws SocketException, IOException, ClassNotFoundException {
    DataInputStream inStream = new DataInputStream(socket.getInputStream());
    int length = inStream.readInt();
    byte[] authMsg = new byte[length];
    inStream.readFully(authMsg, 0, authMsg.length);
    return authMsg;
  }
}
