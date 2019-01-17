import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class Handshake {
    private Arguments arguments;
    private Boolean clientCertOk = false;
    private Boolean serverCertOk = false;
    private X509Certificate clientCert = null;

    /* serverHost and serverPort */
    public String serverHost;
    public int serverPort;

    /* sessionKey and sessionIV */
    public byte[] sessionKey;
    public byte[] sessionIv;


    /* The final destination */
    public String targetHost;
    public int targetPort;

    private VerifyCertificate verifyCertificate = new VerifyCertificate();

    /* Constructor with the given arguments */
    public Handshake(Arguments arguments) {
        this.arguments = arguments;
        if (this.arguments.get("targethost") != null) {
            targetHost = this.arguments.get("targethost");
            targetPort = Integer.parseInt(this.arguments.get("targetport"));
        }
    }

    /* System out print */
    private void log(String msg) {
        System.out.println(msg);
    }

    /* Encode certificate to string */
    private String encodeCertificate(String certFile) throws IOException, CertificateException {
        FileInputStream certificateFile = new FileInputStream(certFile);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(certificateFile);
        return Base64.getEncoder().encodeToString(x509Certificate.getEncoded());
    }

    /* Decode string to certificate */
    private X509Certificate decodeCertificate(String certFile) throws CertificateException {
        byte[] decodedCert = Base64.getDecoder().decode(certFile);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        InputStream inputStream = new ByteArrayInputStream(decodedCert);
        return  (X509Certificate) certificateFactory.generateCertificate(inputStream);
    }

    /* Client - ClientHello message */
    public void ClientHelloMsg(Socket socket) {
        HandshakeMessage handshakeMessage = new HandshakeMessage();
        handshakeMessage.putParameter("MessageType", "ClientHello");
        try {
            handshakeMessage.putParameter("Certificate", encodeCertificate(arguments.get("usercert")));
            handshakeMessage.send(socket);
            log("ClientHello msg sent");
        } catch (IOException e) {
            log("Socket Error - Not able to send ClientHello msg");
        } catch (CertificateException e) {
            log("Certificate Error - Not able to encode client's certificate");
        }
    }

    /* Server - Receive ClientHello message */
    public boolean FromClientHelloMsg(Socket socket) {
        HandshakeMessage handshakeMessage = new HandshakeMessage();
        try {
            handshakeMessage.recv(socket);
            if (handshakeMessage.getParameter("MessageType").equals("ClientHello")) {
                log("Received ClientHello msg");
                clientCert = decodeCertificate(handshakeMessage.getParameter("Certificate"));
                if (verifyCertificate.checkCertificate(clientCert, decodeCertificate(encodeCertificate(arguments.get("cacert"))))) {
                    clientCertOk = true;
                    log("Client's certificate ok");
                    return ServerHelloMsg(socket);
                }
            }
        } catch (IOException e) {
            log("Socket Error - Not able to receive messages");
        } catch (CertificateException e) {
            log("Certificate Error - Not able to decode client's certificate");
        }
        return false;
    }

    /* Server - ServerHello message */
    private boolean ServerHelloMsg(Socket socket) {
        HandshakeMessage handshakeMessage = new HandshakeMessage();
        handshakeMessage.putParameter("MessageType", "ServerHello");
        try {
            handshakeMessage.putParameter("Certificate", encodeCertificate(arguments.get("usercert")));
            handshakeMessage.send(socket);
            log("ServerHello msg sent");
            return true;
        } catch (IOException e) {
            log("Socket Error - Not able to send ServerHello msg");
        } catch (CertificateException e) {
            log("Certificate Error - Not able to encode Server's certificate");
        }
        return false;
    }

    /* Client - Receive ServerHello message */
    public boolean FromServerHelloMsg(Socket socket) {
        HandshakeMessage handshakeMessage = new HandshakeMessage();
        try {
            handshakeMessage.recv(socket);
            if (handshakeMessage.getParameter("MessageType").equals("ServerHello")) {
                log("Received ServerHello msg");
                X509Certificate serverCert = decodeCertificate(handshakeMessage.getParameter("Certificate"));
                if (verifyCertificate.checkCertificate(serverCert, decodeCertificate(encodeCertificate(arguments.get("cacert"))))) {
                    serverCertOk = true;
                    log("Server's certificate ok");
                    return ForwardMsg(socket);
                }
            } else {
                log("Message Error - No ServerHello msg received");
            }
        } catch (IOException e) {
            log("Socket Error - Not able to receive messages at the socket");
        } catch (CertificateException e) {
            log("Certificate Error - Not able to decode the Server's certificate");
        }
        return false;
    }

    /* Client - Forward message */
    private boolean ForwardMsg(Socket socket) {
        HandshakeMessage handshakeMessage = new HandshakeMessage();
        handshakeMessage.putParameter("MessageType", "Forward");
        handshakeMessage.putParameter("TargetHost", targetHost);
        handshakeMessage.putParameter("TargetPort", Integer.toString(targetPort));
        try {
            handshakeMessage.send(socket);
            log("Forward msg sent");
            return true;
        } catch (IOException e) {
            log("Socket Error - Not able to send Forward msg");
        }
        return false;
    }

    /* Server - Receive Forward message */
    public boolean FromClientForwardMsg(Socket socket) {
        HandshakeMessage handshakeMessage = new HandshakeMessage();
        try {
            handshakeMessage.recv(socket);
            if (handshakeMessage.getParameter("MessageType").equals("Forward") && clientCertOk) {
                log("Received Forward msg");
                targetHost = handshakeMessage.getParameter("TargetHost");
                targetPort = Integer.parseInt(handshakeMessage.getParameter("TargetPort"));
                return SessionMsg(socket, clientCert);
            }
        } catch (IOException e) {
            log("Socket Error - Not able to receive messages");
        }
        return false;
    }

    /* Server - Session message */
    private boolean SessionMsg(Socket socket, X509Certificate clientCert) {
        // handshake encryption
        SessionEncrypter sessionEncrypter = new SessionEncrypter(256);
        sessionKey = sessionEncrypter.getSecretKey();
        sessionIv = sessionEncrypter.getIV();

        /* Extract publicKey from client's certificate */
        PublicKey publicKey = clientCert.getPublicKey();

        /* Encryption of key and iv with client's public key */
        byte[] encryptedSessionKey = HandshakeCrypto.encrypt(sessionKey, publicKey);
        byte[] encryptedSessionIV = HandshakeCrypto.encrypt(sessionIv, publicKey);

        /* Encode encrypted as string to send it with handshake message */
        String encodedSessionKey = Base64.getEncoder().encodeToString(encryptedSessionKey);
        String encodedSessionIV = Base64.getEncoder().encodeToString(encryptedSessionIV);

        /* Generate a socket endpoint */
        ServerSocket serverSocket = null; // listen on any free port
        try {
            serverSocket = new ServerSocket(0);
            serverHost = InetAddress.getLocalHost().getHostAddress();
            serverPort = serverSocket.getLocalPort();
            serverSocket.close();
        } catch (IOException e) {
            log("Socket Error - Not able to assign a server socket");
            return false;
        }

        /* ready to send message to client */
        HandshakeMessage handshakeMessage = new HandshakeMessage();
        handshakeMessage.putParameter("MessageType", "Session");
        handshakeMessage.putParameter("SessionKey", encodedSessionKey);
        handshakeMessage.putParameter("SessionIV", encodedSessionIV);
        handshakeMessage.putParameter("ServerHost", serverHost);
        handshakeMessage.putParameter("ServerPort", Integer.toString(serverPort));
        try {
            handshakeMessage.send(socket);
            log("Session msg sent");
            return true;
        } catch (IOException e) {
            log("Socket Error - Not able to send Session message");
        }
        return false;
    }

    /* Client - Receive Session message */
    public boolean FromServerSessionMsg(Socket socket) {
        HandshakeMessage handshakeMessage = new HandshakeMessage();
        try {
            handshakeMessage.recv(socket);
            if (handshakeMessage.getParameter("MessageType").equals("Session") && serverCertOk) {
                log("Received Session msg");
                /* handshake decode of received key and iv - get client's private key */
                PrivateKey privateKeyClient = HandshakeCrypto.getPrivateKeyFromKeyFile(arguments.get("key"));
                byte[] decodedSessionKey = Base64.getDecoder().decode(handshakeMessage.getParameter("SessionKey"));
                byte[] decodedSessionIV = Base64.getDecoder().decode(handshakeMessage.getParameter("SessionIV"));

                /* decrypt session key and iv with client's private key */
                sessionKey = HandshakeCrypto.decrypt(decodedSessionKey, privateKeyClient);
                sessionIv = HandshakeCrypto.decrypt(decodedSessionIV, privateKeyClient);

                /* get serverHost and serverPort */
                serverHost = handshakeMessage.getParameter("ServerHost");
                serverPort = Integer.parseInt(handshakeMessage.getParameter("ServerPort"));

                return true;
            } else {
                log("Message Error - No Session msg received");
            }
        } catch (IOException e) {
            log("Socket Error - Not able to receive messages at the socket");
        }
        return false;
    }

}
