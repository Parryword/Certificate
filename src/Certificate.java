import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

public class Certificate {
    private String fullName;
    private String nickName;
    private PublicKey publicKey;
    private LocalDateTime date;
    private byte[] signature;

    public Certificate(String fullName, String nickName, PublicKey publicKey, long expirationDate) throws NoSuchAlgorithmException {
        this.fullName = fullName;
        this.nickName = nickName;
        this.publicKey = publicKey;
        this.date = LocalDateTime.now();
        date.plusSeconds(expirationDate);
    }

    public void sign(PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        StringBuilder sb = new StringBuilder();
        sb.append(fullName);
        sb.append(nickName);
        sb.append(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        sb.append(date.toString());
        String s = sb.toString();
        System.out.println(s);
        byte[] data = s.getBytes(StandardCharsets.UTF_8);
        Signature sig = Signature.getInstance("SHA1WithRSA");
        sig.initSign(privateKey);
        sig.update(data);
        byte[] signatureBytes = sig.sign();
        this.signature = signatureBytes;
    }

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public String getNickName() {
        return nickName;
    }

    public void setNickName(String nickName) {
        this.nickName = nickName;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public String getExpirationDate() {
        return date.toString();
    }

    public void setExpirationDate(LocalDateTime date) {
        this.date = date;
    }

    public byte[] getSignature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    @Override
    public String toString() {
        return "Certificate{" +
                "fullName='" + fullName + '\'' +
                ", nickName='" + nickName + '\'' +
                ", expirationDate='" + date + '\'' +
                ", publicKey=" + Base64.getEncoder().encodeToString(publicKey.getEncoded()) +
                "\n" +
                ", signature=" + Base64.getEncoder().encodeToString(signature) +
                '}';
    }
}
