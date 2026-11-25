package com.mh1721.handshake;

import java.math.BigInteger;

/**
 * Raw modular exponentiation, the same operation as MHRSA_Pub and MHRSA_Pri.
 * A block is 64 bytes. The public exponent is the 4-byte value 00010001.
 */
final class RsaBox {
    static final int BLOCK = 64;
    static final int EXPONENT_BYTES = 4;

    private RsaBox() {
    }

    static byte[] encrypt(byte[] block) {
        return modPow(block, Keys.PUBLIC_EXPONENT);
    }

    static byte[] decrypt(byte[] block) {
        return modPow(block, Keys.PRIVATE_EXPONENT);
    }

    static byte[] modulus() {
        return hex(Keys.MODULUS);
    }

    static byte[] publicExponent() {
        return hex(Keys.PUBLIC_EXPONENT);
    }

    static byte[] plain() {
        return hex(Keys.PLAIN);
    }

    static byte[] cipher() {
        return hex(Keys.CIPHER);
    }

    private static byte[] modPow(byte[] block, String exponentHex) {
        if (block == null || block.length != BLOCK) {
            throw new IllegalArgumentException("block must be " + BLOCK + " bytes");
        }
        BigInteger modulus = new BigInteger(1, hex(Keys.MODULUS));
        BigInteger exponent = new BigInteger(1, hex(exponentHex));
        BigInteger value = new BigInteger(1, block);
        if (value.compareTo(modulus) >= 0) {
            throw new IllegalArgumentException("block is not smaller than the modulus");
        }
        return fixed(value.modPow(exponent, modulus), BLOCK);
    }

    private static byte[] fixed(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        int start = 0;
        int count = raw.length;
        if (count > 0 && raw[0] == 0) {
            start = 1;
            count--;
        }
        if (count > length) {
            throw new IllegalArgumentException("value does not fit in " + length + " bytes");
        }
        byte[] out = new byte[length];
        System.arraycopy(raw, start, out, length - count, count);
        return out;
    }

    private static byte[] hex(String text) {
        byte[] out = new byte[text.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(text.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
