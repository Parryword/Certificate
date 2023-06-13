import java.io.*;
import java.net.*;
import java.nio.charset.Charset;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.ReentrantLock;

public class Server {
    static PublicKey publicKey;
    static PrivateKey privateKey;

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair keyPair = keyGen.generateKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
        FileOutputStream fos;
        byte[] key = publicKey.getEncoded();
        fos = new FileOutputStream(new File("public.key"));
        fos.write(key);
        fos.flush(); fos.close();


        Certificate c1 = new Certificate("a", "aa", createPublicKey(), 15);
        Certificate c2 = new Certificate("b", "bb", createPublicKey(), 15);
        Certificate c3 = new Certificate("c", "cc", createPublicKey(), 15);
        Certificate c4 = new Certificate("d", "dd", createPublicKey(), 15);
        Certificate c5 = new Certificate("e", "ee", createPublicKey(), 15);
        ArrayList<Certificate> list = new ArrayList<>();
        list.add(c1); list.add(c2); list.add(c3); list.add(c4); list.add(c5);
        for (Certificate c:list
             ) {
            c.sign(privateKey);
        }

        TCPServer tcp = new TCPServer();
        tcp.setList(list);
        tcp.init();
        tcp.loop();
    }

    public static PublicKey createPublicKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair keyPair = keyGen.generateKeyPair();
        return keyPair.getPublic();
    }
}

class TCPServer {
    private static ArrayList<Certificate> list = new ArrayList<>();
    private ServerSocket welcomeSocket;

    public void init() throws IOException {
        welcomeSocket = new ServerSocket(6789);
    }

    public void loop() throws IOException {
        while(true) {
            Socket connectionSocket = welcomeSocket.accept();
            BufferedReader inFromClient = new BufferedReader(new InputStreamReader(connectionSocket.getInputStream()));
            DataOutputStream outToClient = new DataOutputStream(connectionSocket.getOutputStream());

            String s = inFromClient.readLine();
            String[] split = s.split(" ");
            if (s.equals("EXIT")) {
                System.exit(0);
            }
            else if (split.length == 1 || !split[0].equals("GET")) {
                outToClient.writeBytes("400\n");
            } else if (split[0].equals("GET")) {
                String nickname = split[1];
                Certificate temp = null;
                for (Certificate c:list
                     ) {
                    if (c.getNickName().equals(nickname)) {
                        temp = c;
                    }
                }
                if (temp == null) {
                    outToClient.writeBytes("401\n");
                } else if (temp != null) {
                    String name = temp.getFullName();
                    String nickName = temp.getNickName();
                    String date = temp.getExpirationDate();

                    System.out.println(temp);
                    String publicKeyEncoded = Base64.getEncoder().encodeToString(temp.getPublicKey().getEncoded());
                    String signatureEncoded = Base64.getEncoder().encodeToString(temp.getSignature());

                    System.out.println("Encoded: " + publicKeyEncoded);
                    System.out.println("Encoded: " + signatureEncoded);

                    StringBuilder sb = new StringBuilder();
                    sb.append("200");
                    sb.append(" ");
                    sb.append(name);
                    sb.append(" ");
                    sb.append(nickName);
                    sb.append(" ");
                    sb.append(publicKeyEncoded);
                    sb.append(" ");
                    sb.append(date);
                    sb.append(" ");
                    sb.append(signatureEncoded);
                    sb.append("\n");
                    outToClient.writeBytes(sb.toString());
                }
            }

            outToClient.writeBytes("Received your message.\n");
        }
    }

    public void setList(ArrayList<Certificate> list) {
        this.list = list;
    }

}
