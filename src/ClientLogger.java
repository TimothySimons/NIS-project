import java.io.IOException;
import java.net.Socket;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.*;
import javax.crypto.Cipher;

public class ClientLogger {
  private final static Logger LOGGER = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);

  public void logMsg(String msg) {
    LOGGER.log(Level.INFO, msg);
  }

  public void logConnection(Socket socket) {
    int localPort = socket.getLocalPort();
    String localHost = socket.getLocalAddress().getHostName();
    int remotePort = socket.getPort();
    String remoteHost = socket.getInetAddress().getHostName();
    String logMsg = String.format("Local host %s on port %d is connected to port %d of remote host %s",
            localHost, localPort, remotePort, localHost);
    LOGGER.log(Level.INFO, "Connection established:\n" + logMsg + "\n");
  }

  public void logRemoteCert(Certificate cert) {
    LOGGER.log(Level.INFO, "Received certificate from connected client:\n" + cert +"\n");
  }

  public void logCompress(int before, int after) {
    LOGGER.log(Level.INFO, "Compressed byte array of size " + before + " to byte array of size " + after + "\n");
  }

  public void logDecompress(int before, int after) {
    LOGGER.log(Level.INFO, "Decompressed byte array of size " + before + " to byte array of size " + after + "\n");
  }

  public void logEncryption(String algSpec, Cipher cipher, byte[] cipherText) {
    String encryptionProvider = cipher.getProvider().getInfo() + '\n';
    LOGGER.log(Level.INFO, "Algorithm specification: " + algSpec + "\n" + encryptionProvider + "Cipher text: \n" + new String(cipherText));

  }
}
