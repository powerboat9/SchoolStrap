package com.powerboat9.schoolstrap.common;

import sun.security.rsa.RSAKeyPairGenerator;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;

public class Crypt {
    public static final int SYMMETRIC_KEYSIZE = 128;
    public static final int ASYMMETRIC_KEYSIZE = 2048;

    public static final int HASH_SIZE = 32;
    public static final int RSAOUT_SIZE = ASYMMETRIC_KEYSIZE / 8;
    public static final int IV_SIZE = 16;

    public static byte[] hash(byte[] in) {
        try {
            MessageDigest hashDigest = MessageDigest.getInstance("SHA-256");
            return hashDigest.digest(in);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] symmetricEncrypt(byte[] in, SecretKey key, IvParameterSpec iv) {
        try {
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            c.init(Cipher.ENCRYPT_MODE, key, iv);
            return c.doFinal(in);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | InvalidKeyException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] symmetricDecrypt(byte[] in, SecretKey key, IvParameterSpec iv) {
        try {
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            c.init(Cipher.DECRYPT_MODE, key, iv);
            return c.doFinal(in);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | InvalidKeyException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] asymmetricEncrypt(byte[] in, Key key) {
        try {
            Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            c.init(Cipher.ENCRYPT_MODE, key);
            return c.doFinal(in);
        } catch (NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException | NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] asymmetricDecrypt(byte[] in, Key key) {
        try {
            Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            c.init(Cipher.DECRYPT_MODE, key);
            return c.doFinal(in);
        } catch (NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException | NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] asymmetricSign(byte[] in, PrivateKey key) {
        try {
            Signature s = Signature.getInstance("SHA256withRSA");
            s.initSign(key);
            s.update(in);
            return s.sign();
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static boolean asymmetricCheck(byte[] in, PublicKey key) {
        try {
            Signature s = Signature.getInstance("SHA256withRSA");
            s.initVerify(key);
            return s.verify(in);
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            e.printStackTrace();
            return false;
        }
    }

    public static SecretKey symmetricKeygen(int size) {
        try {
            KeyGenerator gen = KeyGenerator.getInstance("AES");
            gen.init(size, new SecureRandom());
            return gen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static SecretKey symmetricKeygen() {
        return symmetricKeygen(SYMMETRIC_KEYSIZE);
    }

    public static KeyPair asymmetricKeygen(int size) {
        RSAKeyPairGenerator rsaGen = new RSAKeyPairGenerator();
        rsaGen.initialize(size, new SecureRandom());
        return rsaGen.generateKeyPair();
    }

    public static KeyPair asymmetricKeygen() {
        return asymmetricKeygen(ASYMMETRIC_KEYSIZE);
    }

    public static IvParameterSpec ivGen() {
        return new IvParameterSpec(Crypt.symmetricKeygen().getEncoded());
    }

    public static byte[] cat(byte[][] b) {
        int total = 0;
        for (byte[] bb : b) {
            total += bb.length;
        }
        byte[] ret = new byte[total];
        int k = 0;
        for (byte[] bb : b) {
            for (int i = 0; i < bb.length; ++i) {
                ret[i + k] = bb[i];
            }
            k += bb.length;
        }
        return ret;
    }
}

