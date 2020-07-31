package com.debuggor.merlin;

import com.debuggor.utils.NumberUtils;

/**
 * @Author:yong.huang
 * @Date:2020-07-31 17:23
 */
public class Strobe128 {

    private byte[] state;
    private int pos;
    private int pos_begin;
    private int cur_flags;

    private static int STROBE_R = 166;

    private static int FLAG_I = 1;
    private static int FLAG_A = 1 << 1;
    private static int FLAG_C = 1 << 2;
    private static int FLAG_T = 1 << 3;
    private static int FLAG_M = 1 << 4;
    private static int FLAG_K = 1 << 5;

    public Strobe128(byte[] state) {
        this.state = state;
        this.pos = 0;
        this.pos_begin = 0;
        this.cur_flags = 0;
    }


    public static Strobe128 createStrobe(byte[] protocol) {
        byte[] state = initial_state(128);
        Strobe128 strobe128 = new Strobe128(state);


        return strobe128;
    }

    /**
     * pub fn meta_ad(&mut self, data: &[u8], more: bool) {
     * self.begin_op(FLAG_M | FLAG_A, more);
     * self.absorb(data);
     * }
     */
    private void meta_ad(byte[] data, boolean more) {
        begin_op(FLAG_M | FLAG_A, more);
        absorb(data);
    }

    /**
     * // Check if we're continuing an operation
     * if more {
     * assert_eq!(
     * self.cur_flags, flags,
     * "You tried to continue op {:#b} but changed flags to {:#b}",
     * self.cur_flags, flags,
     * );
     * return;
     * }
     * <p>
     * // Skip adjusting direction information (we just use AD, PRF)
     * assert_eq!(
     * flags & FLAG_T,
     * 0u8,
     * "You used the T flag, which this implementation doesn't support"
     * );
     * <p>
     * let old_begin = self.pos_begin;
     * self.pos_begin = self.pos + 1;
     * self.cur_flags = flags;
     * <p>
     * self.absorb(&[old_begin, flags]);
     * <p>
     * // Force running F if C or K is set
     * let force_f = 0 != (flags & (FLAG_C | FLAG_K));
     * <p>
     * if force_f && self.pos != 0 {
     * self.run_f();
     * }
     */
    private void begin_op(int flags, boolean more) {
        // Check if we're continuing an operation
        if (more) {
            return;
        }
        int old_begin = this.pos_begin;
        this.pos_begin = this.pos + 1;
        this.cur_flags = flags;

        byte[] tmp = new byte[2];
        tmp[0] = (byte) old_begin;
        tmp[1] = (byte) flags;
        this.absorb(tmp);

        // Force running F if C or K is set
        boolean force_f = 0 != (flags & (FLAG_C | FLAG_K));
        if (force_f && this.pos != 0) {
            this.run_f();
        }
    }

    /**
     * fn absorb(&mut self, data: &[u8]) {
     * for byte in data {
     * self.state[self.pos as usize] ^= byte;
     * self.pos += 1;
     * if self.pos == STROBE_R {
     * self.run_f();
     * }
     * }
     */
    private void absorb(byte[] data) {
        for (int i = 0; i < data.length; i++) {
            this.state[this.pos] ^= data[i];
            this.pos += 1;
            if (this.pos == STROBE_R) {
                this.run_f();
            }
        }

    }

    /**
     * fn run_f(&mut self) {
     * self.state[self.pos as usize] ^= self.pos_begin;
     * self.state[(self.pos + 1) as usize] ^= 0x04;
     * self.state[(STROBE_R + 1) as usize] ^= 0x80;
     * keccak::f1600(transmute_state(&mut self.state));
     * self.pos = 0;
     * self.pos_begin = 0;
     * }
     */
    private void run_f() {
        this.state[this.pos] ^= this.pos_begin;
        this.state[this.pos + 1] ^= 0x04;
        this.state[STROBE_R + 1] ^= 0x80;
        this.state = runF(this.state, 128);
        this.pos = 0;
        this.pos_begin = 0;
    }

    /**
     * fn overwrite(&mut self, data: &[u8]) {
     * for byte in data {
     * self.state[self.pos as usize] = *byte;
     * self.pos += 1;
     * if self.pos == STROBE_R {
     * self.run_f();
     * }
     * }
     * }
     */
    private void overwrite(byte[] data) {
        for (int i = 0; i < data.length; i++) {
            this.state[this.pos] = data[i];
            this.pos += 1;
            if (this.pos == STROBE_R) {
                this.run_f();
            }
        }
    }

    /**
     * fn squeeze(&mut self, data: &mut [u8]) {
     * for byte in data {
     * *byte = self.state[self.pos as usize];
     * self.state[self.pos as usize] = 0;
     * self.pos += 1;
     * if self.pos == STROBE_R {
     * self.run_f();
     * }
     * }
     * }
     */
    private void squeeze(byte[] data) {
        for (int i = 0; i < data.length; i++) {
            data[i] = this.state[this.pos];
            this.state[this.pos] = 0;
            this.pos += 1;
            if (this.pos == STROBE_R) {
                this.run_f();
            }
        }
    }


    private static byte[] initial_state(int security) {
        if (security != 128 && security != 256) {
            throw new IllegalArgumentException("strobe: security must be set to either 128 or 256");
        }
        byte[] st = new byte[200];
        byte[] b1 = {1, (byte) (STROBE_R + 2), 1, 0, 1, 96};
        byte[] b2 = "STROBEv1.0.2".getBytes();
        System.arraycopy(b1, 0, st, 0, b1.length);
        System.arraycopy(b2, 0, st, b1.length, b2.length);

        st = runF(st, security);
        return st;
    }


    /**
     * runF: applies the STROBE's + cSHAKE's padding and the Keccak permutation
     *
     * @return
     */
    private static byte[] runF(byte[] buf, int security) {
        int duplexRate = 1600 / 8 - security / 4;
        byte[] storage = new byte[duplexRate];
        System.arraycopy(buf, 0, storage, 0, duplexRate);
        long[] state = NumberUtils.xorState(storage);
        Keccak.f1600(state);

        byte[] st = new byte[200];
        int offset = 0;
        for (int i = 0; i < state.length; i++) {
            NumberUtils.int64ToBytes(state[i], st, offset);
            offset += 8;
        }
        return st;
    }

    public static void main(String[] args) {

        byte[] bytes = initial_state(128);
    }
}
