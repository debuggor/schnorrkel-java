package com.debuggor.schnorrkel.sign;

import cafe.cryptography.curve25519.*;
import com.debuggor.schnorrkel.utils.HexUtils;

import java.security.SecureRandom;

/**
 * @Author:yong.huang
 * @Date:2020-07-30 13:25
 */
public class KeyPair {

    private static final RistrettoGeneratorTable ristrettoTable = Constants.RISTRETTO_GENERATOR_TABLE;

    private static byte[] CTX = "substrate".getBytes();

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

    public Signature sign(byte[] data) throws Exception {
        SigningContext ctx = SigningContext.createSigningContext(CTX);
        SigningTranscript t = ctx.bytes(data);

        t.proto_name("Schnorr-sig".getBytes());
        t.commit_point("pk".getBytes(), publicKey.getCompressedRistretto());

        // context, message, A/public_key
        Scalar r = t.witness_scalar(privateKey.getNonce());
        CompressedRistretto R = ristrettoTable.multiply(r).compress();
        t.commit_point("no".getBytes(), R);

        // context, message, A/public_key, R=rG
        Scalar k = t.challenge_scalar("".getBytes());

        Scalar key = Scalar.fromBits(privateKey.getKey());
        Scalar s = k.multiplyAndAdd(key, r);
        r = Scalar.ZERO;
        return new Signature(R, s);
    }

    public static KeyPair fromPublicKey(byte[] pubkey) throws InvalidEncodingException {
        CompressedRistretto compressedRistretto = new CompressedRistretto(pubkey);
        RistrettoElement ristretto = compressedRistretto.decompress();
        PublicKey publicKey = new PublicKey(ristretto);
        return new KeyPair(publicKey, null);
    }

    public boolean verify(byte[] data, byte[] signature) throws Exception {
        Signature sign = Signature.from_bytes(signature);

        SigningContext ctx = SigningContext.createSigningContext(CTX);
        SigningTranscript t = ctx.bytes(data);

        t.proto_name("Schnorr-sig".getBytes());
        t.commit_point("pk".getBytes(), publicKey.getCompressedRistretto());
        t.commit_point("no".getBytes(), sign.getR());

        // context, message, A/public_key, R=rG
        Scalar k = t.challenge_scalar("".getBytes());

        RistrettoElement publicPoint = publicKey.getRistretto();
        RistrettoElement subtract = ristrettoTable.multiply(sign.getS()).subtract(publicPoint.multiply(k));
        CompressedRistretto R = subtract.compress();
        return R.equals(sign.getR());
    }
}
