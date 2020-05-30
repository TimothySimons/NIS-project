import java.io.*;
import java.net.*;
import javax.net.ssl.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.cert.Certificate;
import javax.net.ServerSocketFactory;

// import AsymmetricEncryption;

public class Client {

/**
 * Creates a connection with another client and facilitates the communication
 * between them.
 *
 * @param args specifies whether the client should listen for a connection on a
 * specified <port number> or make a connection to a client <host name>
 * listening on <port number>.
 */
  public static void main(String[] args) {
    /*
     * TODO: use JCommander to read commandline options.
     * Allow user to specify whether they want to generate a public-private key
     * pair or read in this pair from a file.
     * TODO: this main function violates so many best practices; need to clean it up.
     */
     try {
      if(args.length == 1) {
        int portNumber = Integer.parseInt(args[0]);
        Socket socket = listen(portNumber);
        X509Certificate cert = AsymmetricEncryption.loadCert("../resources/alice/alicekeystore.jks", "alice","alice123");
        sendCert(socket, cert);
      } else if (args.length == 2){
        String hostName = args[0];
        int portNumber = Integer.parseInt(args[1]);
        Socket socket = connect(hostName, portNumber);
        X509Certificate cert = receiveCert(socket);
        AsymmetricEncryption.authenticateCert("../resources/alice/alicekeystore.jks", "alice123", "thecaroot", cert);
        System.out.println(cert);
      } else {
        System.err.println("Usage 1: java Client <port number>");
        System.err.println("Usage 2: java Client <host name> <port number>");
        System.exit(1);
      }
    } catch (UnknownHostException e) {
      e.printStackTrace();
    } catch (SocketException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
    } catch (Exception e) {
      e.printStackTrace();
    }
  }


  /**
   * Listens for a connection and returns the associated socket.
   *
   * @param portNumber local port number on which to listen for a connection
   * @return socket associated with the connected client
   */
  private static Socket listen(int portNumber) throws IOException {
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
  private static Socket connect(String hostName, int portNumber)
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
  private static void sendCert(Socket socket, Certificate cert)
  throws SocketException, IOException {
      ObjectOutputStream outputStream = new ObjectOutputStream(socket.getOutputStream());
      outputStream.writeObject(cert);
  }


  /**
   * Receive a Certificate object from the remote host.
   *
   * @param socket endpoint for the communication to the remote host
   * @return signed certificate of the remote host
   */
  private static X509Certificate receiveCert(Socket socket)
  throws SocketException, IOException, ClassNotFoundException {
      ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream());
      X509Certificate cert = (X509Certificate) inStream.readObject();
      return cert;
  }
}







//TODO: make all methods throw the relevant exceptions and catch those exceptions
//      in main


// try {
//   PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
//   BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
//   BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
//   String userInput;
//   while ((userInput = stdIn.readLine()) != null) {
//     out.println(userInput);
//     System.out.println("remote: " + in.readLine());
//   }
// } catch (IOException e) {
//   String hostName = socket.getInetAddress().getHostName();
//   System.err.println("Couldn't get I/O for connection to " + hostName);
// }
