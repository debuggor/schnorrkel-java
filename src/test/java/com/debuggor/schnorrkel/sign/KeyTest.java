package com.debuggor.schnorrkel.sign;

import cafe.cryptography.curve25519.*;
import com.debuggor.schnorrkel.utils.HexUtils;
import com.debuggor.schnorrkel.utils.ScalarUtils;


/**
 * @Author:yong.huang
 * @Date:2020-07-29 23:03
 */
public class KeyTest {

    public static void main(String[] args) {
        byte[] privateKey = HexUtils.hexToBytes("882749e4a5738ba59e7e25b2cd66c41c9037c4950e3a0cd18846df9814a33d79");
        privateKey = ScalarUtils.divide_scalar_bytes_by_cofactor(privateKey);
        System.out.println(HexUtils.bytesToHex(privateKey));

        Scalar scalar = Scalar.fromBits(privateKey);
        RistrettoGeneratorTable table = Constants.RISTRETTO_GENERATOR_TABLE;
        RistrettoElement multiply = table.multiply(scalar);
        CompressedRistretto compress = multiply.compress();
        byte[] bytes = compress.toByteArray();
        System.out.println(HexUtils.bytesToHex(bytes));


    }


}
