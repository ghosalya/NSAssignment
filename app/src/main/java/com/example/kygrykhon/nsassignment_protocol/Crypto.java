package com.example.kygrykhon.nsassignment_protocol;

import java.io.File;
import java.io.FileInputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * Created by Kygrykhon on 4/17/2017.
 */

public class Crypto {
    public static byte[] randomByteGenerator(int byteArrSize) {
        SecureRandom random = new SecureRandom();
        byte[] randomByteArray = new byte[byteArrSize];
        random.nextBytes(randomByteArray);
        return randomByteArray;
    }

    public static byte[] fileToByteArr(File file) throws Exception {
        byte[] byteArray = new byte[(int) file.length()];
        FileInputStream fis = new FileInputStream(file);
        fis.read(byteArray);
        fis.close();
        return byteArray;
    }

    public static byte[] encrypt(Key key, String encryptionMode, byte[] inputByteArray) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        try {
            // create cipher object, initialize the ciphers with the given key
            Cipher cipher = Cipher.getInstance(encryptionMode);
            cipher.init(Cipher.ENCRYPT_MODE,key);

            // takes byte array containing plaintext input; returns byte array containing cipher text as output
            return cipher.doFinal(inputByteArray);
        }

        catch (NoSuchAlgorithmException e) {
            System.out.println("no such algorithm");
            e.printStackTrace();
            throw new NoSuchAlgorithmException();
        }
        catch (NoSuchPaddingException e) {
            System.out.println("no such padding");
            e.printStackTrace();
            throw new NoSuchPaddingException();
        }
        catch (InvalidKeyException e) {
            System.out.println("invalid key");
            e.printStackTrace();
            throw new InvalidKeyException();
        }
        catch (IllegalBlockSizeException e) {
            System.out.println("illegal block size" + e.getMessage());
            e.printStackTrace();
            throw new IllegalBlockSizeException();
        }
        catch (BadPaddingException e) {
            System.out.println("bad padding");
            e.printStackTrace();
            throw new BadPaddingException();
        }
    }

    public static File getFile(String name) {
        //check if file exists, etc
        File file = new File(name);
        if(file.exists()) {
            return file;
        } else {
            return null;
        }
    }

    public static byte[] decrypt(Key key, String decryptionMode, byte[] encryptedByteArray)
    throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

            // create cipher object, initialize the ciphers with the given key
            Cipher cipher = Cipher.getInstance(decryptionMode);
            cipher.init(Cipher.DECRYPT_MODE,key);

            // decryption
            return cipher.doFinal(encryptedByteArray);

    }
}
