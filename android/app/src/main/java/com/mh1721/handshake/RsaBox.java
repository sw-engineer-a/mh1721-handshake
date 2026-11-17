package com.mh1721.handshake;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;

/** Android RSA/ECB/PKCS1Padding with the same key as the Keil firmware. */
final class RsaBox {
    private RsaBox() {
    }

    static byte[] encrypt(byte[] secret) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey());
        return cipher.doFinal(secret);
    }

    static byte[] decrypt(byte[] cipher) throws GeneralSecurityException {
        Cipher cipherBox = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipherBox.init(Cipher.DECRYPT_MODE, privateKey());
        return cipherBox.doFinal(cipher);
    }

    static byte[] modulus() {
        return hex(Keys.MODULUS);
    }

    static byte[] publicExponent() {
        return hex(Keys.PUBLIC_EXPONENT);
    }

    private static PublicKey publicKey() throws GeneralSecurityException {
        return KeyFactory.getInstance("RSA").generatePublic(
                new RSAPublicKeySpec(number(Keys.MODULUS), number(Keys.PUBLIC_EXPONENT)));
    }

    private static PrivateKey privateKey() throws GeneralSecurityException {
        return KeyFactory.getInstance("RSA").generatePrivate(
                new RSAPrivateKeySpec(number(Keys.MODULUS), number(Keys.PRIVATE_EXPONENT)));
    }

    private static BigInteger number(String hex) {
        return new BigInteger(1, hex(hex));
    }

    private static byte[] hex(String text) {
        byte[] out = new byte[text.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(text.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
