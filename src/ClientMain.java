import java.io.IOException;
import java.net.SocketException;
import java.net.UnknownHostException;

public class ClientMain {


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
        // TODO: make into commandline arguments
        String JKSFilePath = "../resources/alice/alicekeystore.jks";
        String alias = "alice";
        String CARootAlias = "thecaroot";
        String password = "alice123";
        Client client = new Client(JKSFilePath, password, alias, CARootAlias);
        client.listenerClientActions(portNumber);
      } else if (args.length == 2){
        String secretMsg = "I love you Alice...";
        String hostName = args[0];
        int portNumber = Integer.parseInt(args[1]);
        String JKSFilePath = "../resources/bob/bobkeystore.jks";
        String alias = "bob";
        String CARootAlias = "thecaroot";
        String password = "bob123";
        Client client = new Client(JKSFilePath, password, alias, CARootAlias);
        client.connectingClientActions(hostName, portNumber, secretMsg);
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
}
