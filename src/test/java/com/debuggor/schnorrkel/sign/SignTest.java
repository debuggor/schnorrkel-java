package com.debuggor.schnorrkel.sign;

import com.debuggor.schnorrkel.utils.HexUtils;

/**
 * @Author:yong.huang
 * @Date:2020-08-02 17:53
 */
public class SignTest {

    public static void main(String[] args) throws Exception {
        KeyPair keyPair = KeyPair.fromSecretSeed(HexUtils.hexToBytes("579d7aa286b37b800b95fe41adabbf0c2a577caf2854baeca98f8fb242ff43ae"), ExpansionMode.Ed25519);

        byte[] message = "test message".getBytes();
        SigningContext ctx = SigningContext.createSigningContext("good".getBytes());
        SigningTranscript t = ctx.bytes(message);
        Signature signature = keyPair.sign(t);
        byte[] sign = signature.to_bytes();
        System.out.println(HexUtils.bytesToHex(sign));


        SigningContext ctx2 = SigningContext.createSigningContext("good".getBytes());
        SigningTranscript t2 = ctx2.bytes(message);
        KeyPair fromPublicKey = KeyPair.fromPublicKey(keyPair.getPublicKey().toPublicKey());
        boolean verify = fromPublicKey.verify(t2, sign);
        System.out.println(verify);
    }

}
