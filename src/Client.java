import java.io.*;
import java.net.*;

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
    Socket socket = null;
    if(args.length == 1) {
      int portNumber = Integer.parseInt(args[0]);
      socket = listen(portNumber);
    } else if (args.length == 2){
      String hostName = args[0];
      int portNumber = Integer.parseInt(args[1]);
      socket = connect(hostName, portNumber);
    } else {
      System.err.println("Usage 1: java Client <port number>");
      System.err.println("Usage 2: java Client <host name> <port number>");
      System.exit(1);
    }

    if (socket != null) {
      try {
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
        String userInput;
        while ((userInput = stdIn.readLine()) != null) {
          out.println(userInput);
          System.out.println("remote: " + in.readLine());
        }
      } catch (IOException e) {
        String hostName = socket.getInetAddress().getHostName();
        System.err.println("Couldn't get I/O for connection to " + hostName);
      }
    } else {
      System.exit(1);
    }
  }

  /**
   * Listens for a connection and returns the associated socket.
   *
   * @param portNumber local port number on which to listen for a connection
   * @return null if the connection is unsuccessful, otherwise the socket
   * associated with the connected client
   */
  public static Socket listen(int portNumber) {
    Socket socket = null;
    try {
      ServerSocket serverSocket = new ServerSocket(portNumber);
      socket = serverSocket.accept();
    } catch (IOException e) {
      System.out.println("Server socket cannot listen on port " + portNumber);
    } finally {
      return socket;
    }
  }

  /**
   * Attempts to connect to a client.
   *
   * @param hostName the name of the remote host
   * @param portNumber the port number on which the remote host is listening
   * @return null if the connection is unsuccessful, otherwise the socket
   * associated with the connected client
   */
  public static Socket connect(String hostName, int portNumber) {
    Socket socket = null;
    try {
      socket = new Socket(hostName, portNumber);
    } catch (UnknownHostException e) {
      System.err.println("Unknown host " + hostName);
      System.exit(1);
    } catch (IOException e) {
      System.err.println("Couldn't get I/O for the connection to " + hostName);
      System.exit(1);
    } finally {
      return socket;
    }
  }
}
