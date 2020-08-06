package com.debuggor.schnorrkel.sign;

import com.debuggor.schnorrkel.utils.HexUtils;


/**
 * @Author:yong.huang
 * @Date:2020-07-29 23:03
 */
public class KeyTest {

    public static void main(String[] args) {
        byte[] seed = HexUtils.hexToBytes("579d7aa286b37b800b95fe41adabbf0c2a577caf2854baeca98f8fb242ff43ae");
        KeyPair keyPair = KeyPair.fromSecretSeed(seed, ExpansionMode.Ed25519);
        PrivateKey privateKey = keyPair.getPrivateKey();
        PublicKey publicKey = keyPair.getPublicKey();

        byte[] key = privateKey.getKey();
        byte[] nonce = privateKey.getNonce();
        byte[] pubkey = publicKey.toPublicKey();
        System.out.println("seed:" + HexUtils.bytesToHex(privateKey.getSeed()));
        System.out.println("key:" + HexUtils.bytesToHex(key));
        System.out.println("nonce:" + HexUtils.bytesToHex(nonce));
        System.out.println("pubkey:" + HexUtils.bytesToHex(pubkey));

        KeyPair pair = KeyPair.generateKeyPair();

    }


}
