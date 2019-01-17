/**
 * Port forwarding client. Forward data
 * between two TCP ports. Based on Nakov TCP Socket Forward Server 
 * and adapted for IK2206.
 *
 * See original copyright notice below.
 * (c) 2018 Peter Sjodin, KTH
 */

/**
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 */

 
import java.io.*;
import java.lang.IllegalArgumentException;
import java.lang.Integer;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.InetAddress;
import java.net.UnknownHostException;

public class ForwardClient
{
    private static final boolean ENABLE_LOGGING = true;
    public static final int DEFAULTSERVERPORT = 2206;
    public static final String DEFAULTSERVERHOST = "localhost";
    public static final String PROGRAMNAME = "ForwardClient";

    private static Arguments arguments;
    private static int serverPort;
    private static String serverHost;
    private Handshake handshake;
    private boolean handshakeCompleted = false;
    private static VerifyCertificate verifyCertificate;

    private void doHandshake() throws IOException, CertificateException {

        /* Connect to forward server server */
        System.out.println("Connect to " +  arguments.get("handshakehost") + ":" + Integer.parseInt(arguments.get("handshakeport")));
        Socket socket = new Socket(arguments.get("handshakehost"), Integer.parseInt(arguments.get("handshakeport")));

        /* This is where the handshake should take place */
        handshake = new Handshake(arguments);
        handshake.ClientHelloMsg(socket);
        if (handshake.FromServerHelloMsg(socket)) {
            if (handshake.FromServerSessionMsg(socket)) {
                Logger.log("Handshake completed!");
                handshakeCompleted = true;
            }
        }

        socket.close();

        serverHost = handshake.serverHost;
        serverPort = handshake.serverPort;
    }

    /*
     * Let user know that we are waiting
     */
    private static void tellUser(ServerSocket listensocket) throws UnknownHostException {
        System.out.println("Client forwarder to target " + arguments.get("targethost") + ":" + arguments.get("targetport"));
        System.out.println("Waiting for incoming connections at " +
                           InetAddress.getLocalHost().getHostAddress() + ":" + listensocket.getLocalPort());
    }
        
    /*
     * Set up client forwarder.
     * Run handshake negotiation, then set up a listening socket and wait for user.
     * When user has connected, start port forwarder thread.
     */
    public void startForwardClient() throws IOException, CertificateException {

        doHandshake();

        // Wait for client. Accept one connection.

        ForwardServerClientThread forwardThread;
        ServerSocket listensocket;
        
        try {
            /* Create a new socket. This is to where the user should connect.
             * ForwardClient sets up port forwarding between this socket
             * and the ServerHost/ServerPort learned from the handshake */
            listensocket = new ServerSocket();
            /* Let the system pick a port number */
            listensocket.bind(null); 
            /* Tell the user, so the user knows where to connect */ 
            tellUser(listensocket);

            Socket clientSocket = listensocket.accept();
            String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
            log("Accepted client from " + clientHostPort);

            if (handshakeCompleted) {
                forwardThread = new ForwardServerClientThread(clientSocket, serverHost, serverPort, handshake.sessionKey, handshake.sessionIv);
                forwardThread.start();
            }
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println(e);
            throw e;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Prints given log message on the standart output if logging is enabled,
     * otherwise ignores it
     */
    public static void log(String aMessage)
    {
        if (ENABLE_LOGGING)
           System.out.println(aMessage);
    }
 
    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--targethost=<hostname>");
        System.err.println(indent + "--targetport=<portnumber>");        
        System.err.println(indent + "--handshakehost=<hostname>");
        System.err.println(indent + "--handshakeport=<portnumber>");        
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");                
    }
    
    /**
     * Program entry point. Reads arguments and run
     * the forward server
     */
    public static void main(String[] args) throws CertificateException {
        try {
            arguments = new Arguments();
            arguments.setDefault("handshakeport", Integer.toString(DEFAULTSERVERPORT));
            arguments.setDefault("handshakehost", DEFAULTSERVERHOST);
            arguments.loadArguments(args);

            /* Verify the name and number of arguments */
            if (args.length != 7 || (arguments.get("usercert") == null || arguments.get("cacert") == null || arguments.get("key") == null || arguments.get("targethost") == null || arguments.get("targetport") == null)) {
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

            if (arguments.get("targetport") == null || arguments.get("targethost") == null) {
                throw new IllegalArgumentException("Target not specified");
            }
        } catch(IllegalArgumentException ex) {
            System.out.println(ex);
            usage();
            System.exit(1);
        } catch (IOException e) {
            e.printStackTrace();
        }
        ForwardClient forwardClient = new ForwardClient();
        try {
            forwardClient.startForwardClient();
        } catch(IOException e) {
           e.printStackTrace();
        }
    }
}
