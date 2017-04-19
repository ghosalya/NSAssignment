
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Scanner;

/**
 * Created by johsi on 14/4/2017.
 */

public class SecStore {
    private static String filePath = "C:\\NSProject\\";
    private static String currentdir;
    private static int portNumber = 4;

    public static void main(String[] args) throws Exception {
        Scanner in = new Scanner(System.in);
        System.out.println("NS Assignment - FileTransfer Client || a 50.005 Computer System Engineering project");
        System.out.println("        by Gede Ria Ghosalya & Keong Johsi");

        if(!checkDownloadPath()){
            System.out.println(filePath+" is not a valid path. Relocating to local directory");
            filePath = System.getProperty("user.dir").toString() + File.separator + "NSProject" + File.separator;
        }

        System.out.println("You IP Address is: "+ InetAddress.getLocalHost().toString());

        // creation of X509Certificate object from 1001685.crt
        X509Certificate ServerCert = getServerCert();

        // creation of Server's private key from privateServer.der
        Key serverprivKey = getPrivateKey("RSA");

        while (true) {
            if(attemptServerVerification(serverprivKey, ServerCert)){
                System.out.println("Transfer successful");
            } else {
                System.out.println("Transfer failed");
            }
        }


    }

    private static boolean checkPathExists(String path) {
        File file = new File(path);
        return (file.exists() && file.isDirectory());
    }

    private static X509Certificate getServerCert()
    throws  FileNotFoundException, CertificateException, IOException{
        currentdir = System.getProperty("user.dir")+"\\";
        InputStream ServerCertFileInputStream = new FileInputStream(currentdir+"1001685.crt");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate ServerCert = (X509Certificate)cf.generateCertificate(ServerCertFileInputStream);
        ServerCertFileInputStream.close();
        return ServerCert;
    }

    private static PrivateKey getPrivateKey(String algorithm)
    throws FileNotFoundException, IOException, NoSuchAlgorithmException, InvalidKeySpecException{
        File keyFile = new File(currentdir+"privateServer.der");
        byte[] privKeyByteArray = new byte[(int)keyFile.length()];
        FileInputStream fis = new FileInputStream(keyFile);
        fis.read(privKeyByteArray); //read file into bytes[]
        fis.close();
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyByteArray);  // represents ASN.1 encoding of private key
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        PrivateKey serverprivKey = keyFactory.generatePrivate(keySpec);
        return serverprivKey;
    }

    private static boolean attemptServerVerification(Key serverprivKey, X509Certificate ServerCert)
    throws IOException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
            InvalidKeyException, BadPaddingException, CertificateEncodingException {
        String algo;
        try (  // try-with-resources statement
               ServerSocket serverSocket = new ServerSocket(portNumber);
               Socket clientSocket = serverSocket.accept();

               // for receiving random message from client
               BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

               // for sending encrypted random message to client
               PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);

               // for sending CA-signed certificate to client
               ObjectOutputStream oout = new ObjectOutputStream(clientSocket.getOutputStream());

               // for receiving file from client upon successful authentication
               ObjectInputStream ois = new ObjectInputStream(clientSocket.getInputStream());

        ) {

            // Initiates conversation with client - receiving random byte array from client
            System.out.println("Expecting random msg");
            byte[] randomByteArray = (byte[]) ois.readObject();
            System.out.println("random msg received");

            // server encrypts random message from client with server's private key
            System.out.println("encrypting random msg");
            byte[] encryptedByteArray = Crypto.encrypt(serverprivKey, "RSA", randomByteArray);
//            System.out.println("length of encrypted byte array: " + encryptedByteArray.length);

            // server sends encrypted message back to client
            System.out.println("sending encrypted random msg bytes");
            oout.writeObject(encryptedByteArray);
            oout.flush();

            // receives client's request for CA-signed certificate
            System.out.println("expecting client request");
            String request = in.readLine();
            System.out.println(request);

            // check if sent ServerCert corresponds to client's received ServerCert
            byte[] derCert = ServerCert.getEncoded();

            // server sends CA-signed certificate object (simultaneously/upon client's request?)
            System.out.println("sending server cert");
            oout.writeObject(ServerCert);
            oout.flush();

            System.out.println("question asking for server's preferred CP");
            in.readLine();

            System.out.print("Prefered CP [1,2]:");
            Scanner scanner = new Scanner(System.in);
            String preferredCP = scanner.next();
            out.println(preferredCP);
            out.flush();


            if (preferredCP.equals("2")) {
                // receives AES secret key (in byte array format) from client
                System.out.println("receiving encrypted AES key");
                byte[] encryptedAESKeyBytes = (byte[]) ois.readObject();

                System.out.println("decrypting AES key");
                byte[] decryptedAESKeyBytes = Crypto.decrypt(serverprivKey, "RSA", encryptedAESKeyBytes);
                SecretKey aesKey = new SecretKeySpec(decryptedAESKeyBytes, 0, decryptedAESKeyBytes.length, "AES");
                serverprivKey = aesKey;
                algo = "AES/ECB/PKCS5Padding";
            } else {
                algo = "RSA/ECB/PKCS1Padding";
            }

            //oout.close(); //we dont need this at this point
            long starttime = System.currentTimeMillis();
            File success = receiveFile(in, out, ois, serverprivKey, algo);
            long endtime = System.currentTimeMillis();
            System.out.println("Estimated time taken(server): "+(endtime-starttime)+ " ms ("+estimatedTime(endtime-starttime)+")");
            System.out.println("Estimated throughput(server): " + 1.0*success.length()/(endtime-starttime) + " b/ms");
            oout.close();
			clientSocket.close();
            return success != null;
        } catch(StreamCorruptedException e) {
            System.out.println("stream corrupted: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    private static File receiveFile(BufferedReader in, PrintWriter out, ObjectInputStream ois, Key serverprivKey, String algo)
    throws ClassNotFoundException, IOException,
        NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        String filename;
        //fetching name
        try{
            filename = in.readLine();
            out.println("Filename received");
        } catch (IOException e) {
            System.out.println("Name not received.");
            filename = "tempfile";
        }
		
		File outputFile = generateOutputFile(filename);

        FileOutputStream fos = new FileOutputStream(outputFile);
        System.out.println("Starts receiving file..");
        while(true) {
            // receives file in byte array format from client and writes bytes into destination file "received.txt"
//            System.out.println("receiving encrypted file bytes");
            byte[] encryptedFileBytes = (byte[]) ois.readObject();
				System.out.print(".");
            if (new String (encryptedFileBytes).equals("end of file byte transfer")) {
                System.out.println("end of file byte transfer reached");
                break;
            }

//            System.out.println("decrypting file bytes");
            byte[] decryptedFileBytes = Crypto.decrypt(serverprivKey, algo, encryptedFileBytes);
//            System.out.println(new String(decryptedFileBytes));
//            System.out.println("writing decrypted file bytes to file");
            fos.write(decryptedFileBytes);
        }

        in.close();
        out.close();
//        oout.close();
        ois.close();
        fos.close();
        return outputFile;
    }

    private static File generateOutputFile(String filename) throws IOException{
        int count = 0;
        String orifilename = filename;
        try {
            File file;
            while (true) {
                file = new File(filePath + filename);
                if (!file.exists()) {
                    file.createNewFile();
                    break;
                } else {
                    filename = " ("+count+")"+orifilename;
                    count++;
                }
            }
            return file;
        } catch (FileNotFoundException fnfe) {
            //shouldnt be the case
        }
        return null;
    }

    private static boolean checkDownloadPath() {
        File path = new File(filePath);
        if(!path.exists()) {
            path.mkdir();
        }

        return path.exists();
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
