package com.powerboat9.schoolstrap.common.network;

import com.powerboat9.schoolstrap.common.Crypt;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;

public abstract class Packet implements Serializable {
    public final byte[] toBytes(PublicKey sendKey, PrivateKey verifyKey) {
        SecretKey aesKey = Crypt.symmetricKeygen();
        byte[] encryptedAESKey = Crypt.asymmetricEncrypt(aesKey.getEncoded(), sendKey);
        byte[] data = this.toBytesRaw();
        byte[] hashedData = Crypt.hash(data);
        byte[] encryptedHash = Crypt.asymmetricSign(hashedData, verifyKey);
        IvParameterSpec iv = Crypt.ivGen();
        byte[] encryptedData = Crypt.symmetricEncrypt(data, aesKey, iv);
        // Combine                     256              16          32          256
        return Crypt.cat(new byte[][] {encryptedAESKey, iv.getIV(), hashedData, encryptedHash, encryptedData});
    }

    // DO NOT USE DIRECTLY
    protected abstract byte[] toBytesRaw();

    public final Packet fromBytes(byte[] data, PrivateKey recKey, PublicKey verifyKey) {
        int dataLength;
        if ((dataLength = data.length - Crypt.RSAOUT_SIZE * 2 - Crypt.IV_SIZE - Crypt.HASH_SIZE) < 0) return null;

        byte[] bytesEncryptedAES = new byte[Crypt.RSAOUT_SIZE];
        System.arraycopy(data, 0, bytesEncryptedAES, 0, Crypt.RSAOUT_SIZE);
        byte[] bytesDecryptedAES = Crypt.asymmetricDecrypt(bytesEncryptedAES, recKey);
        if (bytesDecryptedAES.length != Crypt.SYMMETRIC_KEYSIZE) return null;
        SecretKey keyAES = new SecretKeySpec(bytesDecryptedAES, "AES");

        byte[] bytesIV = new byte[Crypt.IV_SIZE];
        System.arraycopy(data, Crypt.RSAOUT_SIZE, bytesIV, 0, Crypt.IV_SIZE);
        IvParameterSpec iv = new IvParameterSpec(bytesIV);

        byte[] bytesHash = new byte[Crypt.HASH_SIZE];
        System.arraycopy(data, Crypt.RSAOUT_SIZE + Crypt.IV_SIZE, bytesHash, 0, Crypt.HASH_SIZE);

        byte[] bytesSignedHash = new byte[Crypt.RSAOUT_SIZE];
        System.arraycopy(data, Crypt.RSAOUT_SIZE + Crypt.IV_SIZE + Crypt.HASH_SIZE, bytesSignedHash, 0, Crypt.RSAOUT_SIZE);

        byte[] bytesEncryptedData = new byte[dataLength];
        System.arraycopy(data, Crypt.RSAOUT_SIZE * 2 + Crypt.IV_SIZE + Crypt.HASH_SIZE, bytesEncryptedData, 0, dataLength);

        byte[] bytesDecryptedData = Crypt.symmetricDecrypt(bytesEncryptedData, keyAES, iv);
        if (!Crypt.asymmetricCheck(bytesSignedHash, verifyKey)) return null;
        if (!Crypt.hash(bytesDecryptedData).equals(bytesHash)) return null;
        return this.fromBytesRaw(bytesDecryptedData);
    }

    // DO NOT USE DIRECTLY
    protected abstract Packet fromBytesRaw(byte[] data);
}
