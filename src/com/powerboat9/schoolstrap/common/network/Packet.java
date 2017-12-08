package com.powerboat9.schoolstrap.common.network;

import com.powerboat9.schoolstrap.common.Crypt;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.Serializable;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;

public abstract class Packet implements Serializable {
    public final byte[] toBytes(PublicKey sendKey, PrivateKey verifyKey) {
        SecretKey aesKey = Crypt.symmetricKeygen();
        byte[] encryptedAESKey = Crypt.asymmetricEncrypt(aesKey.getEncoded(), sendKey);
        byte[] data = this.toBytesRaw();
        byte[] hashedData = Crypt.hash(data);
        IvParameterSpec iv = Crypt.ivGen();
        byte[] encryptedData = Crypt.symmetricEncrypt(data, aesKey, iv);
        // Combine                     256              16          32          16
        return Crypt.cat(new byte[][] {encryptedAESKey, iv.getIV(), hashedData, encryptedData});
    }

    // DO NOT USE DIRECTLY
    protected abstract byte[] toBytesRaw();

    public final Packet fromBytes(byte[] data, PrivateKey recKey) {
        int dataLength;
        if ((dataLength = data.length - Crypt.RSAOUT_SIZE - Crypt.IV_SIZE - Crypt.HASH_SIZE) < 0) return null;
        byte[] bytesEncryptedAES = new byte[Crypt.RSAOUT_SIZE];
        System.arraycopy(data, 0, bytesEncryptedAES, 0, Crypt.RSAOUT_SIZE);
        byte[] bytesIV = new byte[Crypt.IV_SIZE];
        System.arraycopy(data, Crypt.RSAOUT_SIZE, bytesIV, 0, Crypt.IV_SIZE);
        byte[] bytesHash = new byte[Crypt.HASH_SIZE];
        System.arraycopy(data, Crypt.RSAOUT_SIZE + Crypt.IV_SIZE, bytesHash, 0, Crypt.HASH_SIZE);
        byte[] bytesEncryptedData = new byte[dataLength];
        System.arraycopy(data, Crypt.RSAOUT_SIZE + Crypt.IV_SIZE + Crypt.HASH_SIZE, bytesEncryptedData, 0, dataLength);
        byte[] bytesDecryptedAES = Crypt.asymmetricDecrypt(bytesEncryptedAES, recKey)
        SecretKey key = new SecretKeySpec()
    }

    // DO NOT USE DIRECTLY
    protected abstract void fromBytesRaw(byte[] data);
}
