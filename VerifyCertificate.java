import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class VerifyCertificate {

    /* Encode certificate to string */
    public String encodeCertificate(String certFile) throws IOException, CertificateException {
        FileInputStream certificateFile = new FileInputStream(certFile);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(certificateFile);
        return Base64.getEncoder().encodeToString(x509Certificate.getEncoded());
    }

    /* Decode string to certificate */
    public X509Certificate decodeCertificate(String certFile) throws CertificateException {
        byte[] decodedCert = Base64.getDecoder().decode(certFile);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        InputStream inputStream = new ByteArrayInputStream(decodedCert);
        return  (X509Certificate) certificateFactory.generateCertificate(inputStream);
    }

    /* Verify certificates */
    public boolean checkCertificate(X509Certificate userCert, X509Certificate caCert) {
        try {
            userCert.verify(caCert.getPublicKey());
            userCert.checkValidity();
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
