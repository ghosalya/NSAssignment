
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Scanner;
import java.util.concurrent.CyclicBarrier;

/**
 * Created by johsi on 14/4/2017.
 */


public class Client {

    public static void main(String[] args) throws Exception {

        Scanner in = new Scanner(System.in);
        System.out.println("NS Assignment - FileTransfer Client || a 50.005 Computer System Engineering project");
        System.out.println("        by Gede Ria Ghosalya & Keong Johsi");

        if(args.length == 0) {
            clientCLInterface();
        } else if (args.length == 2){
            File transferingfile = Crypto.getFile(args[1]);
            clientHandleFile(args[0], transferingfile);
        } else {
            System.out.println("Invalid number of arguments, starting CLI.");
            clientCLInterface();
        }
    }

    static void clientCLInterface() {
        Scanner in = new Scanner(System.in);

        while (true) {
            String IPinput = "";
            while (!checkValidIPAddress(IPinput)) {
                System.out.println("Target IP Address:");
                IPinput = in.nextLine();
                if(IPinput == "") IPinput = "localhost";
                if (!checkValidIPAddress(IPinput) && !(IPinput=="localhost")) {
                    System.out.println("Invalid IP!!");
                }
            }

            String filename = "";
            File file = null;
            while (file == null) {
                System.out.println("Filename:");
                filename = in.nextLine();
                if ((file = Crypto.getFile(filename)) != null) {
                    //valid file is inputted
                    break;
                } else {

                    System.out.println("Invalid file name/path..");
                }
            }

            System.out.println("Transferring "+filename+" to "+IPinput);
            if(clientHandleFile(IPinput, file)) {
                System.out.println("Transfer successful");
            } else {
                System.out.println("Transfer failed");
            }
        }
        //System.out.println("Thank you for using our service!");
    }

    static boolean checkValidIPAddress (String ipaddress) {
        //check if ipaddress is a legitimate string for IP Addresses
        return ipaddress.matches("\\d+\\.\\d+\\.\\d+\\.\\d+");
    }

    public static boolean clientHandleFile(final String ipaddress, final File file) {
        if(file==null) {
            System.out.println("Null file");
            return false;
        } else {
            try {

                boolean success = clientHandleTransfer(ipaddress, file);

                return success;
            } catch (Exception e) {
                System.out.println("wierd..");
                e.printStackTrace();
                return false;
            }
        }
    }

    public static boolean clientHandleTransfer(String ipaddress, File sentfile) //returns whether it is successful
    throws IOException, ClassNotFoundException {
        String currentdir = System.getProperty("user.dir")+"\\";
        int portNum = 4;

        System.out.println("Connecting...");
        Socket echoSocket = new Socket(ipaddress, portNum);

        // for receiving server-encrypted random message
        BufferedReader in = new BufferedReader(new InputStreamReader(echoSocket.getInputStream()));

        // for receiving CA-signed certificate from server
        ObjectInputStream ois = new ObjectInputStream(echoSocket.getInputStream());

        // for requesting CA-signed certificate
        PrintWriter out = new PrintWriter(echoSocket.getOutputStream(), true);

        // for sending file to server upon authentication
        ObjectOutputStream oout = new ObjectOutputStream(echoSocket.getOutputStream());

        Key serverPublicKey = VerifyServer(in, ois, out, oout);
        if (serverPublicKey!=null) { // handshake for file upload
            System.out.println("handshake");
            //byte[] fileBytes;
            //try {
            //    fileBytes = Crypto.fileToByteArr(sentfile);  // variable file object
            //} catch (Exception e) {
            //    System.out.println("File to send error:"+e.getMessage());
            //    return false;
            //} //error with file

            System.out.println("requesting server's preferred CP");
            out.println("please state your preferred CP");
            out.flush();

            System.out.println("awaiting server's response");
            String preferredCP = in.readLine();


            if (preferredCP.contains("2")) {  // accepts "2" or "CP2"
                //changes publickey to new AES key for encryption
                serverPublicKey = CP2KeyGeneration(serverPublicKey, oout);
            }

            //sending file name
            out.println(sentfile.getName());

            // encrypts file in byte array format using server's public key
            System.out.println("sending encrypted file bytes");
            long starttime = System.currentTimeMillis();
            //boolean successful = CP(fileBytes, serverPublicKey, oout, preferredCP);
			boolean successful = CP(sentfile, serverPublicKey, oout, preferredCP);
            long endtime = System.currentTimeMillis();
            System.out.println("Estimated time taken: "+estimatedTime(endtime-starttime));
            System.out.println("Estimated throughput: " + 1.0*sentfile.length()/(endtime-starttime) + " b/ms");
//            System.out.println("transfer complete");
            return successful;

        }

        else
        {  // close connection
            out.println("Bye!");
            echoSocket.close();
            in.close();
            ois.close();
            out.close();
            oout.close();
            return false;
        }
    }

    private static Key VerifyServer(BufferedReader in, ObjectInputStream ois, PrintWriter out, ObjectOutputStream oout)
    throws IOException, ClassNotFoundException{
        // generation of random byte array
        byte[] randomByteArray = Crypto.randomByteGenerator(50);

        System.out.println("sending a random byte array");
        oout.writeObject(randomByteArray);
        oout.flush();
        oout.reset();

        // receiving encrypted byte array from server
        System.out.println("receiving encrypted random byte array");
        byte[] encryptedByteArray = (byte[]) ois.readObject();

        out.println("Please send your certificate signed by CA");
        out.flush();

        // creation of X509Certificate object from CA.crt
        X509Certificate CAcert = null;
        try {
            String currentdir = System.getProperty("user.dir")+File.separator;
            InputStream CAFileInputStream = new FileInputStream(currentdir+"CA.crt");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            CAcert = (X509Certificate) cf.generateCertificate(CAFileInputStream);
            CAFileInputStream.close();
        } catch (Exception ce) {
            ce.printStackTrace();
            System.out.println("Failed to retrieve CA Certificate:"+ce.getMessage());
            return null;
        }


        // extraction of public key from CAcert - why do we need this?
        PublicKey CAPublicKey = CAcert.getPublicKey();

        // receives signed certificate from server
        System.out.println("receiving server cert");
        X509Certificate ServerCert = (X509Certificate) ois.readObject();

        try {
            // check if certificate is currently valid
            ServerCert.checkValidity();
            // verify certificate
            ServerCert.verify(CAPublicKey);

            // checks that incoming ServerCert corresponds to ServerCert sent by server
            byte[] derCert = ServerCert.getEncoded();
//            String pemCert = Base64.encodeToString(derCert, 0);
            // System.out.println("incoming ServerCert: " + pemCert);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Server Certificate error - "+e.getMessage());
            return null;
        }

        // extraction of public key from ServerCert
        Key serverPublicKey = ServerCert.getPublicKey();

        // decrypts server-encrypted random message with server's public key
        // create cipher object, initialize the cipher with the given key, using RSA decryption mode
        byte[] decryptedByteArray;
        try {
            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.DECRYPT_MODE, serverPublicKey);
            decryptedByteArray = rsaCipher.doFinal(encryptedByteArray);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Decrypting error - "+e.getMessage());
            return null;
        }

        if(!Arrays.equals(randomByteArray, decryptedByteArray)) {
            return null;
        } else {
            return serverPublicKey;
        }
    }

    private static Key CP2KeyGeneration(Key serverPublicKey, ObjectOutputStream oout) {
        // generates AES secret key
        try {
            System.out.println("generating AES secret key");
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            SecretKey aesKey = keyGenerator.generateKey();

            // send RSA-encrypted AES secret key in byte array format to server
            System.out.println("encrypting secret key");
            byte[] aesKeyBytes = aesKey.getEncoded();
            byte[] encryptedAESKeyBytes = Crypto.encrypt(serverPublicKey, "RSA/ECB/PKCS1Padding", aesKeyBytes);

            System.out.println("sending secret key");
            oout.writeObject(encryptedAESKeyBytes);

            return aesKey;
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Error in generating AES key:"+e.getMessage());
            return null;
        }
    }

    //private static boolean CP (byte[] fileBytes, Key key, ObjectOutputStream oout, String CP) {
    private static boolean CP (File sentfile, Key key, ObjectOutputStream oout, String CP) throws FileNotFoundException{
        int chunksize;
        int start = 0;
        String algo;

        if (CP.contains("2")) {
            chunksize = 1024;
            algo = "AES/ECB/PKCS5Padding";
        } else {
            chunksize = 117;
            algo = "RSA/ECB/PKCS1Padding";
        }
		
		int k = chunksize;
		
		BufferedInputStream fis = new BufferedInputStream(new FileInputStream(sentfile));
		byte[] chunk = new byte[chunksize];
        try {
            while (k == chunksize) {
                //int end = Math.min(fileBytes.length, start + chunksize);
				k = fis.read(chunk,0,chunksize);
                //chunk = Arrays.copyOfRange(fileBytes, start, end);
                //start += chunksize;
                oout.writeObject(Crypto.encrypt(key, algo, chunk));
                oout.flush();
            }
        oout.writeObject("end of file byte transfer".getBytes());
        oout.flush();
        } catch (Exception e) {
            System.out.println("Error during file transfer: "+e.getMessage());
            e.printStackTrace();
//            try{
//            oout.writeObject("end of file byte transfer".getBytes());
//            oout.flush(); } catch (Exception fe) {fe.printStackTrace();}
            return false;
        }
        return true;
    }

    private static String estimatedTime(long millis) {
        String timing = "";
        long hours = (millis/(3600*1000)) ;
        if(hours>0) {
            timing += hours+" hrs ";
        }

        long minutes = (millis%(3600*1000)/(60*1000));
        if(minutes>0) {
            timing += minutes+" min ";
        }

        long seconds = (millis%(60*1000)/1000);
        if(seconds>0) {
            timing += seconds+" s ";
        }

        long remmil = millis%1000;
        timing += remmil+" ms";
        return timing;
    }

}
