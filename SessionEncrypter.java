import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SessionEncrypter {
    private static final String METHOD = "AES/CTR/NoPadding";
    private SessionKey sessionKey;
    private Cipher cipher;
    private IvParameterSpec ivParameterSpec;

    public SessionEncrypter(Integer keylength) {
        try {
            this.sessionKey = new SessionKey(keylength);
            this.cipher = Cipher.getInstance(METHOD);
            byte[] iv = new byte[cipher.getBlockSize()];
            new SecureRandom().nextBytes(iv);
            this.ivParameterSpec = new IvParameterSpec(iv);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public SessionEncrypter(byte[] key, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException {
        this.cipher = Cipher.getInstance(METHOD);
        this.sessionKey = new SessionKey(key);
        this.ivParameterSpec = new IvParameterSpec(iv);
    }

    public CipherOutputStream openCipherOutputStream(OutputStream output) {
        try {
            this.cipher.init(Cipher.ENCRYPT_MODE, this.sessionKey.getSecretKey(), this.ivParameterSpec);
            return new CipherOutputStream(output, cipher);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public byte[] getSecretKey() {
        return this.sessionKey.getSecretKey().getEncoded();
    }

    public byte[] getIV() {
        return this.ivParameterSpec.getIV();
    }
}
