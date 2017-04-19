package com.example.kygrykhon.nsassignment_protocol;


//import sun.misc.BASE64Encoder;
import android.util.Base64;

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
    private static final String filePath = "C:\\NSProject\\";
    private static String currentdir;
    private static int portNumber = 4;

    public static void main(String[] args) throws Exception {
        Scanner in = new Scanner(System.in);
        System.out.println("NS Assignment - FileTransfer Client || a 50.005 Computer System Engineering project");
        System.out.println("        by Gede Ria Ghosalya & Keong Johsi");

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
            System.out.println("length of encrypted byte array: " + encryptedByteArray.length);

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

            System.out.println("retrieving server's preferred CP");
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

            oout.close(); //we dont need this at this point
            boolean success = receiveFile(in, out, ois, serverprivKey, algo, "name");
            return success;
        } catch(StreamCorruptedException e) {
            System.out.println("stream corrupted: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    private static boolean receiveFile(BufferedReader in, PrintWriter out, ObjectInputStream ois, Key serverprivKey, String algo, String filename)
    throws ClassNotFoundException, IOException,
        NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        FileOutputStream fos = new FileOutputStream(generateOutputFile(filename));

        while(true) {
            // receives file in byte array format from client and writes bytes into destination file "received.txt"
            System.out.println("receiving encrypted file bytes");
            byte[] encryptedFileBytes = (byte[]) ois.readObject();
            if (new String (encryptedFileBytes).equals("end of file byte transfer")) {
                System.out.println("end of file byte transfer reached");
                break;
            }

            System.out.println("decrypting file bytes");
            byte[] decryptedFileBytes = Crypto.decrypt(serverprivKey, algo, encryptedFileBytes);

            System.out.println("writing decrypted file bytes to file");
            fos.write(decryptedFileBytes);
        }

        in.close();
        out.close();
//        oout.close();
        ois.close();
        fos.close();
        return true;
    }

    private static File generateOutputFile(String filename) throws IOException{
        int count = 0;
        try {
            File file;
            while (true) {
                file = new File(filePath + filename);
                if (!file.exists()) {
                    file.createNewFile();
                    break;
                } else {
                    filename = filename + " ("+count+")";
                }
            }
            return file;
        } catch (FileNotFoundException fnfe) {
            //shouldnt be the case
        }
        return null;
    }

}
