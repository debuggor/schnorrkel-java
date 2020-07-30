package com.debuggor.schnorrkel;

import cafe.cryptography.curve25519.CompressedRistretto;
import cafe.cryptography.curve25519.RistrettoElement;
import cafe.cryptography.curve25519.RistrettoGeneratorTable;
import cafe.cryptography.curve25519.Scalar;
import com.debuggor.utils.ScalarUtils;
import org.spongycastle.util.encoders.Hex;

import static cafe.cryptography.curve25519.Constants.RISTRETTO_GENERATOR_TABLE;

/**
 * @Author:yong.huang
 * @Date:2020-07-29 23:03
 */
public class KeyTest {

    public static void main(String[] args) {
        byte[] privateKey = Hex.decode("aa534fd470760f70a1d23fa875f59741e58aef15854a973df5f15156e87fc815");

        privateKey = Hex.decode("882749e4a5738ba59e7e25b2cd66c41c9037c4950e3a0cd18846df9814a33d79");
        privateKey = ScalarUtils.divide_scalar_bytes_by_cofactor(privateKey);
        System.out.println(Hex.toHexString(privateKey));

        Scalar scalar = Scalar.fromBits(privateKey);
        RistrettoGeneratorTable table = RISTRETTO_GENERATOR_TABLE;
        RistrettoElement multiply = table.multiply(scalar);
        CompressedRistretto compress = multiply.compress();
        byte[] bytes = compress.toByteArray();
        System.out.println(Hex.toHexString(bytes));

    }


}
