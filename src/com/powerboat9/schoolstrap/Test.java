package com.powerboat9.schoolstrap;

import com.powerboat9.schoolstrap.common.Crypt;
import com.powerboat9.schoolstrap.common.network.Packet;

import java.security.KeyPair;

public class Test {
    public static KeyPair RSA_KEY = Crypt.asymmetricKeygen();

    public static void main(String[] args) {
        Packet p = new Packet() {
            private String s;

            @Override
            protected byte[] toBytesRaw() {
                return new byte[0];
            }

            @Override
            protected void fromBytesRaw(byte[] data) {
                if (data.length > 0) {
                    throw new RuntimeException("LOL Nope");
                }
            }
        };
        byte[] in = p.toBytes(RSA_KEY.getPublic(), RSA_KEY.getPrivate());
        p.fromBytes(in, RSA_KEY.getPrivate());
        System.out.println(in.length);
    }
}
