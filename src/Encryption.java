import java.io.*;
import java.security.*;
import java.util.zip.*;

/**
* The class contains general encryption functionality.
*
* The two subclasses, SymmetricEncryption and AsymmetricEncryption, share the
* functionality implemented in this class.
*/
public class Encryption {
  private static final ClientLogger logger = new ClientLogger();

  /**
  * Compresses a byte array.
  *
  * @param msg byte array to be compressed
  * @return byte array containing the compressed message
  *
  */
  public static byte[] compress(byte[] msg) throws IOException, DataFormatException {
    Deflater compresser = new Deflater();
    compresser.setInput(msg);
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream(msg.length);
    compresser.finish();
    byte[] buffer = new byte[1024];
    while(!compresser.finished()) {
      int count = compresser.deflate(buffer);
      outputStream.write(buffer, 0, count);
    }
    outputStream.close();
    byte[] compressedMsg = outputStream.toByteArray();
    logger.logCompress(msg.length, compressedMsg.length);
    return compressedMsg;
  }


  /**
  * Decompresses a byte array.
  *
  * @param compressedMsg byte array containing the compressed message
  * @return byte array containing the decompressed message
  */
  public static byte[] decompress(byte[] compressedMsg) throws IOException, DataFormatException {
    Inflater decompresser = new Inflater();
    decompresser.setInput(compressedMsg);
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream(compressedMsg.length);
    byte[] buffer = new byte[1024];
    while(!decompresser.finished()) {
      int count = decompresser.inflate(buffer);
      outputStream.write(buffer, 0, count);
    }
    outputStream.close();
    byte[] msg = outputStream.toByteArray();
    logger.logDecompress(compressedMsg.length, msg.length);
    return msg;
  }

  /**
  * Computes the hash of a message
  *
  * @param msg byte array to be compressed
  * @param hashAlg hashing algorithm specification
  * @return byte array the hashed message
  *
  */
  public static byte[] computeHash(byte[] msg, String hashAlg) throws NoSuchAlgorithmException {
    MessageDigest md = MessageDigest.getInstance(hashAlg);
    md.update(msg);
    byte[] hash = md.digest();
    return hash;
  }
}
