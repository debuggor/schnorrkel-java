package com.debuggor.schnorrkel.utils;

/**
 * Scalar tooling
 * Elliptic curve utilities not provided by curve25519-dalek,
 * including some not so safe utilities for managing scalars and points.
 * https://github.com/w3f/schnorrkel/blob/master/src/scalars.rs
 *
 * @Author:yong.huang
 * @Date:2020-07-30 10:11
 */
public class ScalarUtils {

    public static byte[] divide_scalar_bytes_by_cofactor(byte[] scalar) {
        int low = 0;
        for (int i = scalar.length - 1; i >= 0; i--) {
            int b = scalar[i] & 0xFF;
            int r = b & 0b00000111;
            b >>= 3;
            b += low;
            low = r << 5;
            scalar[i] = (byte) b;
        }
        return scalar;
    }


}
