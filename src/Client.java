import java.io.*;
import java.net.*;
import javax.net.ssl.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.cert.Certificate;
import java.util.Arrays;
import javax.net.ServerSocketFactory;


public class Client {
  private String alias;
  private String password;
  private KeyStore keyStore;
  private PrivateKey privateKey;
  private PublicKey publicKey;
  private X509Certificate cert;
  private X509Certificate CARootCert;

  public Client(String JKSFilePath, String password, String alias, String CARootAlias) throws Exception {
    this.alias = alias;
    this.password = password;
    this.keyStore = AsymmetricEncryption.loadJKS(JKSFilePath, alias, password);
    this.privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
    this.cert = (X509Certificate) keyStore.getCertificate(alias);
    this.publicKey = cert.getPublicKey();
    this.CARootCert = (X509Certificate) keyStore.getCertificate(CARootAlias);
  }


  public void listenerClientActions(int portNumber) throws Exception {
    Socket socket = listen(portNumber);

    sendCert(socket);
    X509Certificate remoteCert = receiveCert(socket);
    AsymmetricEncryption.authenticateCert(this.keyStore, this.password, this.CARootCert, remoteCert);

    byte[] authMsgOut = AsymmetricEncryption.createAuthMsg(2048, this.privateKey);
    sendBytes(socket, authMsgOut);
    byte[] authMsgIn = receiveBytes(socket);
    PublicKey remotePublicKey = remoteCert.getPublicKey();
    AsymmetricEncryption.verifyAuthMsg(authMsgIn, remotePublicKey);
  }


  public void connectingClientActions(String hostName, int portNumber) throws Exception {
    Socket socket = connect(hostName, portNumber);

    X509Certificate remoteCert = receiveCert(socket);
    AsymmetricEncryption.authenticateCert(this.keyStore, this.password, this.CARootCert, remoteCert);
    sendCert(socket);

    byte[] authMsgIn = receiveBytes(socket);
    PublicKey remotePublicKey = remoteCert.getPublicKey();
    AsymmetricEncryption.verifyAuthMsg(authMsgIn, remotePublicKey);
    byte[] authMsgOut = AsymmetricEncryption.createAuthMsg(2048, this.privateKey);
    sendBytes(socket, authMsgOut);

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
      X509Certificate remoteCert = (X509Certificate) inStream.readObject();
      return remoteCert;
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
