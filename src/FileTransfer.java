import javax.crypto.Cipher;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.InputMismatchException;
import java.util.List;
import java.util.Scanner;
import java.security.*;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.zip.CRC32;

public class FileTransfer {
    public static void main(String[] args) throws Exception {
        System.out.println("Please enter your command.");
        Scanner scanner = new Scanner(System.in);
        String inp = scanner.nextLine();
        while(true) {
            if (inp.equalsIgnoreCase("makekeys")) {
                keyGen();
                break;
            } else if (inp.equalsIgnoreCase("server")) {
                serverMode(scanner);
                break;
            } else if (inp.equalsIgnoreCase("client")) {
                clientMode(scanner);
                break;
            }
            else{
                System.out.println("Invalid input, please enter a valid argument.");
                inp = scanner.nextLine();
            }
        }
    }

    private static void keyGen(){
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(4096); // you can use 2048 for faster key generation
            KeyPair keyPair = gen.genKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();
            try (ObjectOutputStream oos = new ObjectOutputStream(
                    new FileOutputStream(new File("public.bin")))) {
                oos.writeObject(publicKey);
            }
            try (ObjectOutputStream oos = new ObjectOutputStream(
                    new FileOutputStream(new File("private.bin")))) {
                oos.writeObject(privateKey);
            }
        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace(System.err);
        }
    }

    private static void serverMode(Scanner scanner)throws Exception{
        System.out.println("Please enter the name of the file that contains the private key.");
        String fileName  = scanner.nextLine();
        System.out.println("Please enter a port number.");
        int portNum;
        while(true) {
            try {
                portNum = scanner.nextByte();
                break;
            } catch (InputMismatchException e) {
                System.out.println("Noninteger detected. Please enter a port number.");
                scanner.nextLine();
            }
        }

        try (ServerSocket serverSocket = new ServerSocket(portNum)){
            Socket clientSocket = serverSocket.accept();
            ObjectInputStream inputMsgStream = new ObjectInputStream(clientSocket.getInputStream());
            int chunkAmt=0;
            int expeceted=-1;
            Key key=null;
            List<byte[]> dataList = new ArrayList<byte[]>();
            ObjectOutputStream os = new ObjectOutputStream(clientSocket.getOutputStream());
            while(true){
                Message inputMsg= (Message) inputMsgStream.readObject();
                if(inputMsg.getType().equals(MessageType.DISCONNECT)){
                    new PrintStream(clientSocket.getOutputStream(),true,"UTF-8").println("Disconnected from server");
                    clientSocket.close();
                    serverSocket.close();
                }
                else if(inputMsg.getType().equals(MessageType.START)){
                    try {
                        chunkAmt= (int) Math.ceil(  ((double) ((StartMessage) inputMsg).getSize()) /   ((double) ((StartMessage) inputMsg).getChunkSize())      );
                        ObjectInputStream in = new ObjectInputStream((new FileInputStream(fileName)));
                        PrivateKey pKey = (PrivateKey) in.readObject();
                        Cipher cipher = Cipher.getInstance("RSA");
                        cipher.init(Cipher.UNWRAP_MODE,pKey);
                        key = cipher.unwrap(((StartMessage) inputMsg).getEncryptedKey(),"AES",Cipher.SECRET_KEY);
                        os.writeObject(new AckMessage(0));
                        expeceted=0;
                    }
                    catch (Exception e){
                        new ObjectOutputStream(clientSocket.getOutputStream()).writeObject(new AckMessage(-1));
                        expeceted=-1;
                    }
                }
                else if(inputMsg.getType().equals(MessageType.STOP)){
                    new ObjectOutputStream(clientSocket.getOutputStream()).writeObject(new AckMessage(-1));
                    expeceted=-1;
                    dataList.clear();
                }
                else if(inputMsg.getType().equals(MessageType.CHUNK)){
                    if(expeceted==((Chunk) inputMsg).getSeq()) {
                        if (expeceted != chunkAmt) {
                            byte[] chunkData = ((Chunk) inputMsg).getData();
                            Cipher cipher = Cipher.getInstance("AES");
                            cipher.init(Cipher.DECRYPT_MODE, key);
                            byte[] decryptedDat = cipher.doFinal(chunkData);
                            CRC32 crc = new CRC32();
                            crc.update(decryptedDat);
                            if (crc.getValue() == ((Chunk) inputMsg).getCrc()) {
                                expeceted++;
                                dataList.add(decryptedDat);
                            }
                            os.writeObject(new AckMessage(expeceted));
                        }
                        else{
                            System.out.println("Transfer complete");
                        }
                    }
                }
            }
        }

    }

    private static void clientMode(Scanner scanner)throws Exception{
        System.out.println("Please enter the name of the file that contains the public key.");
        String fileName = scanner.nextLine();
        System.out.println("Please enter  the host that will be connected to.");
        String host = scanner.nextLine();
        System.out.println("Please enter a port number.");
        int portNum;
        while(true) {
            try {
                portNum = scanner.nextByte();
                break;
            } catch (InputMismatchException e) {
                System.out.println("Noninteger detected. Please enter a port number.");
                scanner.nextLine();
            }
        }
        try (Socket socket = new Socket(host,portNum)) {

        }
    }
}
