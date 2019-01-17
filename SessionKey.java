import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class SessionKey {
    private static final String ALGORITHM = "AES";
    private SecretKey secretKey;

    public SessionKey(Integer keylength) {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
            keyGenerator.init(keylength);
            this.secretKey = keyGenerator.generateKey();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public SessionKey(byte[] key) {
        try {
            this.secretKey = new SecretKeySpec(key, 0, key.length, ALGORITHM);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public SecretKey getSecretKey() {
        return this.secretKey;
    }

    public String encodeKey() {
        return Base64.getEncoder().encodeToString(this.secretKey.getEncoded());
    }
}
