import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Scanner;

public class Client {
    static PublicKey serverPublicKey;
    public static void main(String[] args) throws Exception {
        // Get server public key
        byte[] keyBytes = Files.readAllBytes(new File("public.key").toPath());
        X509EncodedKeySpec spec2 = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        serverPublicKey = kf.generatePublic(spec2);

        while (true) {
            String q = getInput("Enter a query:");
            if (q.equals("EXIT")) {
                send(q);
                System.exit(0);
            }
            String reply = sendAndReceive(q);
            String[] s = reply.split(" ");
            String status = s[0];
            if (status.equals("400")) {
                System.out.println("Incorrect command.");
            } else if (status.equals("401")) {
                System.out.println("User does not exist");
            } else if (status.equals("200")) {
                System.out.println("User found.");
                // GET CERTIFICATE COMPONENTS & VERIFY
                String name = s[1];
                String nickname = s[2];
                String publicKey = s[3];
                String date = s[4];
                String signature = s[5];
                StringBuilder sb = new StringBuilder();
                sb.append(name);
                sb.append(nickname);
                sb.append(publicKey);
                sb.append(date);
                String merge = sb.toString();

                System.out.println("Encoded: " + publicKey);
                System.out.println("Encoded: " + signature);
                System.out.println(verify(merge, signature));
                LocalDateTime expDate = LocalDateTime.parse(date);
                LocalDateTime currentDate = LocalDateTime.now();

                Duration diff = Duration.between(currentDate, expDate);
                System.out.println(expDate);
                System.out.println(currentDate);

                if (Math.abs(diff.getSeconds()) > 15) {
                    System.out.println("Certficiate expired.");
                } else {
                    System.out.println("Certificate is valid.");
                }
            }
        }
    }

    public static boolean verify(String plainText, String signature) throws Exception {
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initVerify(serverPublicKey);
        System.out.println(plainText);
        byte[] data = plainText.getBytes(StandardCharsets.UTF_8);
        sig.update(data);
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return sig.verify(signatureBytes);


    }

    public static void send(String line) throws IOException {
        String modifiedSentence;
        // Socket Output
        Socket clientSocket = new Socket("localhost", 6789);
        DataOutputStream outToServer = new DataOutputStream(
                clientSocket.getOutputStream());
        // Send it to remote host
        outToServer.writeBytes(line + '\n');
    }

    public static String sendAndReceive(String line) throws IOException, NoSuchAlgorithmException {
        String reply;
        // Socket Output
        Socket clientSocket = new Socket("localhost", 6789);
        DataOutputStream outToServer = new DataOutputStream(
                clientSocket.getOutputStream());
        // Socket Input
        BufferedReader inFromServer = new BufferedReader(new
                InputStreamReader(clientSocket.getInputStream()));
        // Send it to remote host
        outToServer.writeBytes(line + '\n');
        // Read from remote host
        reply = inFromServer.readLine();
        // Display the sentence
        System.out.println("FROM SERVER: " + reply);
        return reply;
    }

    public static String getInput() {
        Scanner input = new Scanner(System.in);
        String s;
        try {
            s = input.nextLine();
            return s;
        } catch (Exception e) {
            e.printStackTrace();
            input.reset();
        }
        return null;
    }

    public static String getInput(String prompt) {
        System.out.println("Enter a query...");
        Scanner input = new Scanner(System.in);
        String s;
        try {
            s = input.nextLine();
            return s;
        } catch (Exception e) {
            e.printStackTrace();
            input.reset();
        }
        return null;
    }

}


