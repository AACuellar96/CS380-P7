import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.interfaces.RSAPrivateKey;
import java.util.*;
import java.security.*;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.zip.CRC32;
public class fileEncDec {
    public static void main(String[] args) throws Exception {
        final KeyGenerator keygen = KeyGenerator.getInstance("AES");
        final SecureRandom random = new SecureRandom();
        keygen.init(random);

        final SecretKey key = keygen.generateKey();
        System.out.println(key.getEncoded());

        final ObjectInputStream keyIn = new ObjectInputStream(new FileInputStream("public.bin"));
        final Key publicKey = (Key) keyIn.readObject();

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.WRAP_MODE, publicKey);
        final byte[] wrappedKey = cipher.wrap(key);
        final ObjectInputStream keyIn2 = new ObjectInputStream(new FileInputStream("private.bin"));
        final Key privateKey = (Key) keyIn2.readObject();

        cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.UNWRAP_MODE, privateKey);
        final SecretKey key2 = (SecretKey) cipher.unwrap(wrappedKey, "RSA", Cipher.SECRET_KEY);
        System.out.println(key2.getEncoded());

    }
}
