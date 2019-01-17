/**
 * Port forwarding server. Forward data
 * between two TCP ports. Based on Nakov TCP Socket Forward Server 
 * and adapted for IK2206.
 *
 * Original copyright notice below.
 * (c) 2018 Peter Sjodin, KTH
 */

/**
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 */
 
import java.io.*;
import java.lang.Integer;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.InetSocketAddress;

public class ForwardServer
{
    private static final boolean ENABLE_LOGGING = true;
    public static final int DEFAULTSERVERPORT = 2206;
    public static final String DEFAULTSERVERHOST = "localhost";
    public static final String PROGRAMNAME = "ForwardServer";
    private static Arguments arguments;
    private Handshake handshake;
    private boolean handshakeCompleted = false;
    private static VerifyCertificate verifyCertificate;

    private ServerSocket handshakeSocket;
    
    private ServerSocket listenSocket;
    private String targetHost;
    private int targetPort;
    
    /**
     * Do handshake negotiation with client to authenticate, learn 
     * target host/port, etc.
     */
    private void doHandshake() throws Exception {

        Socket clientSocket = handshakeSocket.accept();
        String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
        Logger.log("Incoming handshake connection from " + clientHostPort);

        /* This is where the handshake should take place */
        handshake = new Handshake(arguments);
        if (handshake.FromClientHelloMsg(clientSocket)) {
            if (handshake.FromClientForwardMsg(clientSocket)) {
                Logger.log("Handshake completed!");
                handshakeCompleted = true;
            }
        }

        clientSocket.close();

        /* listenSocket is a new socket where the ForwardServer waits for the 
         * client to connect. The ForwardServer creates this socket and communicates
         * the socket's address to the ForwardClient during the handshake, so that the 
         * ForwardClient knows to where it should connect (ServerHost/ServerPort parameters).
         */
        listenSocket = new ServerSocket();
        listenSocket.bind(new InetSocketAddress(handshake.serverHost, handshake.serverPort));

        /* The final destination. The ForwardServer sets up port forwarding
         * between the listenSocket (ie., ServerHost/ServerPort) and the target.
         */
        targetHost = handshake.targetHost;
        targetPort = handshake.targetPort;
    }

    /**
     * Starts the forward server - binds on a given port and starts serving
     */
    public void startForwardServer()
    //throws IOException
        throws Exception
    {
 
        // Bind server on given TCP port
        int port = Integer.parseInt(arguments.get("handshakeport"));
        try {
            handshakeSocket = new ServerSocket(port);
        } catch (IOException ioe) {
           throw new IOException("Unable to bind to port " + port);
        }

        log("Nakov Forward Server started on TCP port " + port);
 
        // Accept client connections and process them until stopped
        while(true) {
            ForwardServerClientThread forwardThread;
           try {
               doHandshake();

               if (handshakeCompleted) {
                   forwardThread = new ForwardServerClientThread(listenSocket, targetHost, targetPort, handshake.sessionKey, handshake.sessionIv);
                   forwardThread.start();
               }
           } catch (IOException e) {
               throw e;
           }
        }
    }
 
    /**
     * Prints given log message on the standart output if logging is enabled,
     * otherwise ignores it
     */
    public void log(String aMessage)
    {
        if (ENABLE_LOGGING)
           System.out.println(aMessage);
    }
 
    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--handshakeport=<portnumber>");        
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");                
    }

    /**
     * Program entry point. Reads settings, starts check-alive thread and
     * the forward server
     */
    public static void main(String[] args)
    {
        try {
            arguments = new Arguments();
            arguments.setDefault("handshakeport", Integer.toString(DEFAULTSERVERPORT));
            arguments.setDefault("handshakehost", DEFAULTSERVERHOST);
            arguments.loadArguments(args);

            /* Verify the name and number of arguments */
            if (args.length != 4 || (arguments.get("usercert") == null || arguments.get("cacert") == null || arguments.get("key") == null)) {
                System.out.println("Bad arguments");
                usage();
                System.exit(1);
            }

            /* Verify given certificates from command line */
            verifyCertificate = new VerifyCertificate();
            String encodedCaCert = verifyCertificate.encodeCertificate(arguments.get("cacert"));
            String encodedUserCert = verifyCertificate.encodeCertificate(arguments.get("usercert"));

            X509Certificate caCert = verifyCertificate.decodeCertificate(encodedCaCert);
            X509Certificate userCert = verifyCertificate.decodeCertificate(encodedUserCert);

            if (verifyCertificate.checkCertificate(caCert, caCert) && verifyCertificate.checkCertificate(userCert, caCert)) {
                System.out.println("Entered certificates were verified");
            } else {
                System.out.println("Certificate Error - Check again the given arguments");
                System.exit(1);
            }
        } catch(IllegalArgumentException ex) {
            System.out.println(ex);
            usage();
            System.exit(1);
        } catch (CertificateException | IOException e) {
            e.printStackTrace();
        }

        ForwardServer srv = new ForwardServer();
        try {
           srv.startForwardServer();
        } catch (Exception e) {
           e.printStackTrace();
        }
    }
 
}
