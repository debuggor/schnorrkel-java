package com.debuggor.schnorrkel;

import cafe.cryptography.curve25519.Constants;
import cafe.cryptography.curve25519.RistrettoElement;
import cafe.cryptography.curve25519.RistrettoGeneratorTable;
import cafe.cryptography.curve25519.Scalar;
import com.debuggor.utils.HexUtils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * @Author:yong.huang
 * @Date:2020-07-30 13:25
 */
public class KeyPair {

    private static final RistrettoGeneratorTable ristrettoTable = Constants.RISTRETTO_GENERATOR_TABLE;

    private final PublicKey publicKey;
    private final PrivateKey privateKey;

    public KeyPair(PublicKey publicKey, PrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public static KeyPair fromSecretSeed(byte[] seed) {
        PrivateKey privateKey = new PrivateKey(seed);
        byte[] key = privateKey.getKey();
        RistrettoElement ristretto = ristrettoTable.multiply(Scalar.fromBits(key));
        PublicKey publicKey = new PublicKey(ristretto);
        return new KeyPair(publicKey, privateKey);
    }

    public static KeyPair generateKeyPair() {
        SecureRandom random = new SecureRandom();
        byte[] seed = new byte[32];
        random.nextBytes(seed);
        return fromSecretSeed(seed);
    }

    public byte[] sign(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-512");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return null;
    }

    public boolean verify(byte[] data, byte[] signature) {
        return false;
    }


    public static void main(String[] args) {
        String seed = "85fbb24afae251ef60b53a44a9cf263254df2079e58d33770e5a9879797b87cc";
        KeyPair keyPair = KeyPair.fromSecretSeed(HexUtils.hexToBytes(seed));
        PrivateKey privateKey = keyPair.getPrivateKey();
        System.out.println(HexUtils.bytesToHex(privateKey.getH()));

        PublicKey publicKey = keyPair.getPublicKey();
        System.out.println(HexUtils.bytesToHex(publicKey.toPublicKey()));
    }

}
