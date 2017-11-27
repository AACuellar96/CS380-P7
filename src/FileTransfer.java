import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.*;
import java.security.*;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.zip.CRC32;

public class FileTransfer {
    public static void main(String[] args) throws Exception {
        if(args.length>0) {
            if (args[0].equalsIgnoreCase("makekeys")) {
                keyGen();
                System.out.println("Keys generated.");
            } else if (args[0].equalsIgnoreCase("server")) {
                serverMode(args[1], Integer.parseInt(args[2]));
            } else if (args[0].equalsIgnoreCase("client")) {
                clientMode(args[1], args[2], Integer.parseInt(args[3]));
            } else {
                System.out.println("Invalid arguments.");
            }
        }
        else{
            System.out.println("No arguments detected.");
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

    private static void serverMode(String fileName, int portNum)throws Exception{
        try (ServerSocket serverSocket = new ServerSocket(portNum)){
            Socket clientSocket = serverSocket.accept();
            ObjectInputStream inputMsgStream = new ObjectInputStream(clientSocket.getInputStream());
            int chunkAmt=0;
            int expected=-1;
            Key key=null;
            String copyFile="Output.txt";
            ObjectOutputStream os = new ObjectOutputStream(clientSocket.getOutputStream());
            while(true){
                Message inputMsg= (Message) inputMsgStream.readObject();
                if(inputMsg.getType().equals(MessageType.DISCONNECT)){
                    new PrintStream(clientSocket.getOutputStream(),true,"UTF-8").println("Disconnected from server");
                    clientSocket.close();
                    serverSocket.close();
                    break;
                }
                else if(inputMsg.getType().equals(MessageType.START)){
                    try {
                        chunkAmt= (int) Math.ceil(  ((double) ((StartMessage) inputMsg).getSize()) /   ((double) ((StartMessage) inputMsg).getChunkSize())      );
                        ObjectInputStream in = new ObjectInputStream((new FileInputStream(fileName)));
                        PrivateKey privateKey = (PrivateKey) in.readObject();
                        Cipher cipher = Cipher.getInstance("RSA");
                        cipher.init(Cipher.UNWRAP_MODE,privateKey);
                        key = cipher.unwrap(((StartMessage) inputMsg).getEncryptedKey(),"AES",Cipher.SECRET_KEY);
                        copyFile = "CopyOf"+((StartMessage) inputMsg).getFile();
                        expected=0;
                        os.writeObject(new AckMessage(0));
                    }
                    catch (Exception e){
                        os.writeObject(new AckMessage(-1));
                        expected=-1;
                    }
                }
                else if(inputMsg.getType().equals(MessageType.STOP)){
                    new ObjectOutputStream(clientSocket.getOutputStream()).writeObject(new AckMessage(-1));
                    expected=-1;
                }
                else if(inputMsg.getType().equals(MessageType.CHUNK)){
                    if(expected==((Chunk) inputMsg).getSeq()) {
                        if (expected < chunkAmt) {
                            Cipher cipher = Cipher.getInstance("AES");
                            cipher.init(Cipher.DECRYPT_MODE, key);
                            byte[] decryptedDat = cipher.doFinal(((Chunk) inputMsg).getData());
                            CRC32 crc = new CRC32();
                            crc.update(decryptedDat);
                            if ((int) crc.getValue() == ((Chunk) inputMsg).getCrc()) {
                                expected++;
                                if(expected==1){
                                    new FileOutputStream(copyFile).write(decryptedDat);
                                }
                                else {
                                    new FileOutputStream(copyFile,true).write(decryptedDat);
                                }
                                System.out.println("Chunk received [" + expected + "/" + chunkAmt + "].");
                                os.writeObject(new AckMessage(expected));
                            }
                        }
                        if(expected==chunkAmt){
                            System.out.println("Transfer complete.");
                            System.out.println("Output path: " + copyFile);
                            System.out.println("");
                            expected=-1;
                            chunkAmt=0;
                            key=null;
                            copyFile="Output.txt";
                        }
                    }
                }
            }
        }

    }

    private static void clientMode(String fileName,String host, int portNum)throws Exception{
        try (Socket socket = new Socket(host,portNum)) {
            System.out.println("Connected to server: " + host + "/" + socket.getInetAddress().getHostAddress());
            ObjectOutputStream objectOut = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream objectInp = new ObjectInputStream(socket.getInputStream());
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            SecretKey sessionKey = keyGen.generateKey();
            Cipher cipher = Cipher.getInstance("RSA");
            PublicKey publicKey =(PublicKey) new ObjectInputStream(new FileInputStream(fileName)).readObject();
            cipher.init(Cipher.WRAP_MODE,publicKey);
            byte[] wrappedKey = cipher.wrap(sessionKey);
             while(true){
                System.out.println("Enter path: ");
                String filePath;
                Scanner scanner = new Scanner(System.in);
                while (true) {
                    filePath = scanner.nextLine();
                    if (new File(filePath).exists())
                        break;
                    System.out.println("Enter a valid path: ");
                }
                System.out.println("Enter chunk size [1024]: ");
                int size;
                try {
                    size = scanner.nextInt();
                } catch (InputMismatchException e) {
                    size = 1024;
                }
                StartMessage start = new StartMessage(filePath, wrappedKey, size);
                objectOut.writeObject(start);
                int chunkAmt = (int) Math.ceil(start.getSize() / (double) start.getChunkSize());
                int seqNum = ((AckMessage) objectInp.readObject()).getSeq();
                if (seqNum == 0) {
                    File file = new File(filePath);
                    System.out.println("Sending: " + filePath + ". File size: " + (int) file.length());
                    System.out.println("Sending " + chunkAmt + " chunks.");
                    FileInputStream fileInp = new FileInputStream(file);
                    Cipher encryptCipher = Cipher.getInstance("AES");
                    encryptCipher.init(Cipher.ENCRYPT_MODE, sessionKey);
                    while (seqNum < chunkAmt) {
                        byte[] data;
                        if(start.getChunkSize()*(seqNum+1)<=file.length()) {
                            data = new byte[start.getChunkSize()];
                        }
                        else{
                            data = new byte[(int) file.length()%start.getChunkSize()];
                        }
                       fileInp.read(data);
                       CRC32 crc = new CRC32();
                       crc.update(data);
                       byte[] encryptedData = encryptCipher.doFinal(data);
                       objectOut.writeObject(new Chunk(seqNum, encryptedData, (int) crc.getValue()));
                       seqNum = ((AckMessage) objectInp.readObject()).getSeq();
                       System.out.println("Chunks completed [" + seqNum + "/" + chunkAmt + "].");
                    }
                }
                System.out.println("Would you like to 1. transfer a new file or 2. disconnect. Any other input besides 1 or 2 will default to disconnect.");
                int choice=2;
                try {
                    scanner.nextLine();
                    choice = Integer.parseInt(scanner.nextLine());
                }
                catch (Exception e){
                    System.out.println("Invalid input detected, defaulting to disconnect.");
                }
                if(choice!=1 && choice!=2){
                    System.out.println("Invalid input detected, defaulting to disconnect.");
                    choice=2;
                }
                if(choice!=1){
                    objectOut.writeObject(new DisconnectMessage());
                    socket.close();
                    break;
                }
            }
        }
    }
}
