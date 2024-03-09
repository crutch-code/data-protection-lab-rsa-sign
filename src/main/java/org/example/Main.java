package org.example;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class Main {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        lab3();
        lab4();
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public static String byteToString (byte[] arr) {
        StringBuilder builder = new StringBuilder();
        for (byte b : arr){
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    }

    public static void lab3(){
        System.out.println("------------------------------------lab-3------------------------------------");
        RSA rsa = new RSA();
        String inputString= "Witchers exist to kill monsters. " +
                "How can I do this if real monsters, in comparison with which even a dragon looks like an " +
                "innocent puppy, roam the world, hiding behind ideals, faith or law?\n" +
                "The Witcher";

        System.out.println("Encrypting the message: " + inputString);
        System.out.println("Open key - is: " + byteToString(rsa.openKey()));
        System.out.println("Close key - is: " + byteToString(rsa.closeKey()));
        // encryption
        byte[] cipher = rsa.openExpKeyPow(inputString.getBytes());
        System.out.println("Encrypted: " + byteToString(cipher));
        // decryption
        byte[] plain = rsa.closeKeyExpPow(cipher);
        System.out.println("Plain message is: " + new String(plain));
        System.out.println("------------------------------------lab-3------------------------------------");
    }

    public static void lab4() throws NoSuchAlgorithmException {
        System.out.println("\n\n\n------------------------------------lab-4------------------------------------");
        RSA bobRsa = new RSA();
        MessageDigest hash = MessageDigest.getInstance("SHA256");
        String bob = "Hello, my name is Bob. I want to encrypt this text so that an attacker cannot read it";
        System.out.println("Bob's hash digest: " + byteToString(hash.digest(bob.getBytes())));
        String hashString = byteToString(hash.digest(bob.getBytes(StandardCharsets.UTF_8)));
        byte[] sign = bobRsa.closeKeyExpPow(hashString.getBytes());
        byte[] cipher = bobRsa.closeKeyExpPow(bob.getBytes());

        System.out.println("Encrypted: " + byteToString(cipher));
        System.out.println("Sign: " + byteToString(sign));

        System.out.println("\n\n\nThan bob send, to alice message and sign.");
        System.out.println("After received, Alice needs to apply the public key to " +
                "the message and signature. \nHash the received message with MD5 and " +
                "compare it with the MD5 value from the signature\n\n\n");
        System.out.println("Received sign md5 digest: " + new String(bobRsa.openExpKeyPow(sign)));
        System.out.println("Received message : " + new String(bobRsa.openExpKeyPow(cipher)));
        System.out.println(
                "Alice checkup md5 digest: " + byteToString(
                        hash.digest(bobRsa.openExpKeyPow(cipher))
                )
        );
        // decryption
        System.out.println("------------------------------------lab-4------------------------------------");
    }
}