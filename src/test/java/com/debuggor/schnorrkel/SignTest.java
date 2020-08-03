package com.debuggor.schnorrkel;

import com.debuggor.utils.HexUtils;

/**
 * @Author:yong.huang
 * @Date:2020-08-02 17:53
 */
public class SignTest {

    public static void main(String[] args) throws Exception {
        KeyPair keyPair = KeyPair.fromSecretSeed(HexUtils.hexToBytes("579d7aa286b37b800b95fe41adabbf0c2a577caf2854baeca98f8fb242ff43ae"));

        byte[] message = {1, 2, 3};
        Signature signature = keyPair.sign(message);
        byte[] sign = signature.to_bytes();

        System.out.println(HexUtils.bytesToHex(sign));

        boolean verify = keyPair.verify(message, sign);
        System.out.println(verify);
    }

}
