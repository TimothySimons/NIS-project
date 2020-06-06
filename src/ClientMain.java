import java.io.IOException;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.file.*;

public class ClientMain {


  public static void main(String[] args) {
     try {
      if(args.length == 5) {
        Client client = new Client(args[0], args[1], args[2], args[3]);
        int portNumber = Integer.parseInt(args[4]);
        client.listeningClientActions(portNumber);
      } else if (args.length == 7){
        Client client = new Client(args[0], args[1], args[2], args[3]);
        String hostName = args[4];
        int portNumber = Integer.parseInt(args[5]);
        String secretMsg = readSecretMsg(args[6]);
        client.connectingClientActions(hostName, portNumber, secretMsg);
      } else {
        System.out.println("Usage 1: java ClientMain <JKS-filepath> <alias> <password> <ca-root-alias> <port-number>");
        System.out.println("Usage 2: java ClientMain <JKS-filepath> <alias> <password> <ca-root-alias> <host name> <port number> <secret-msg-filepath");
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

  private static String readSecretMsg(String msgFilepath) throws IOException {
    String secretMsg = "";
    secretMsg = new String(Files.readAllBytes(Paths.get(msgFilepath)));
    return secretMsg;
  }
}
