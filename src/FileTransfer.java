import javax.crypto.Cipher;
import java.security.interfaces.RSAPrivateKey;
import java.util.InputMismatchException;
import java.util.Scanner;
import java.security.*;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;

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
            while(true){
                Message inputMsg= (Message) inputMsgStream.readObject();
                if(inputMsg.getType().equals(MessageType.DISCONNECT)){
                    new PrintStream(clientSocket.getOutputStream(),true,"UTF-8").println("Disconnected from server");
                    clientSocket.close();
                    serverSocket.close();
                }
                else if(inputMsg.getType().equals(MessageType.START)){
                    try {
                        ObjectInputStream in = new ObjectInputStream((new FileInputStream(fileName)));
                        RSAPrivateKey pKey = (RSAPrivateKey) in.readObject();
                        Cipher cipher = Cipher.getInstance("RSA");
                        cipher.init(Cipher.UNWRAP_MODE,pKey);
                        Key key = cipher.unwrap(((StartMessage) inputMsg).getEncryptedKey(),"AES",Cipher.SECRET_KEY);
                        new ObjectOutputStream(clientSocket.getOutputStream()).writeObject(new AckMessage(0));
                    }
                    catch (Exception e){
                        new ObjectOutputStream(clientSocket.getOutputStream()).writeObject(new AckMessage(-1));
                    }
                    clientSocket.close();
                    serverSocket.close();
                }
                else if(inputMsg.getType().equals(MessageType.STOP)){
                    new ObjectOutputStream(clientSocket.getOutputStream()).writeObject(new AckMessage(-1));
                    clientSocket.close();
                    serverSocket.close();
                }
                else if(inputMsg.getType().equals(MessageType.CHUNK)){
                    clientSocket.close();
                    serverSocket.close();
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
