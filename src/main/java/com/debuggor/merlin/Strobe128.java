package com.debuggor.merlin;

import com.debuggor.utils.NumberUtils;

import java.util.Arrays;

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

    public static Strobe128 createStrobe(byte[] protocol) throws Exception {
        byte[] state = initial_state(128);
        Strobe128 strobe = new Strobe128(state);
        strobe.meta_ad(protocol, false);
        return strobe;
    }

    public void meta_ad(byte[] data, boolean more) throws Exception {
        this.begin_op(FLAG_M | FLAG_A, more);
        this.absorb(data);
    }

    public void ad(byte[] data, boolean more) throws Exception {
        this.begin_op(FLAG_A, more);
        this.absorb(data);
    }

    public void prf(byte[] data, boolean more) throws Exception {
        this.begin_op(FLAG_I | FLAG_A | FLAG_C, more);
        this.squeeze(data);
    }

    public void key(byte[] data, boolean more) throws Exception {
        this.begin_op(FLAG_I | FLAG_A | FLAG_C, more);
        this.overwrite(data);
    }


    private void begin_op(int flags, boolean more) throws Exception {
        // Check if we're continuing an operation
        if (more) {
            if (this.cur_flags != flags) {
                throw new Exception("You tried to continue op " + this.cur_flags + " but changed flags to " + flags);
            }
            return;
        }

        // Skip adjusting direction information (we just use AD, PRF)
        if ((flags & FLAG_T) != 0) {
            throw new Exception("You used the T flag, which this implementation doesn't support");
        }

        int old_begin = this.pos_begin;
        this.pos_begin = this.pos + 1;
        this.cur_flags = flags;

        byte[] tmp = {(byte) old_begin, (byte) flags};
        this.absorb(tmp);

        // Force running F if C or K is set
        boolean force_f = 0 != (flags & (FLAG_C | FLAG_K));

        if (force_f && this.pos != 0) {
            this.run_f();
        }
    }

    private void absorb(byte[] data) {
        for (int i = 0; i < data.length; i++) {
            this.state[this.pos] ^= data[i];
            this.pos += 1;
            if (this.pos == STROBE_R) {
                this.run_f();
            }
        }

    }

    private void run_f() {
        this.state[this.pos] ^= this.pos_begin;
        this.state[this.pos + 1] ^= 0x04;
        this.state[STROBE_R + 1] ^= 0x80;
        this.state = runF(this.state, 200);
        this.pos = 0;
        this.pos_begin = 0;
    }

    private void overwrite(byte[] data) {
        for (int i = 0; i < data.length; i++) {
            this.state[this.pos] = data[i];
            this.pos += 1;
            if (this.pos == STROBE_R) {
                this.run_f();
            }
        }
    }

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

        int duplexRate = 1600 / 8 - security / 4;
        st = runF(st, duplexRate);
        return st;
    }


    /**
     * runF: applies the STROBE's + cSHAKE's padding and the Keccak permutation
     *
     * @return
     */
    private static byte[] runF(byte[] buf, int duplexRate) {
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

    public static void main(String[] args) throws Exception {
        Strobe128 strobe = createStrobe("Conformance Test Protocol".getBytes());

        strobe.meta_ad("ms".getBytes(), false);
        strobe.meta_ad("g".getBytes(), true);

        byte[] msg = new byte[1024];
        Arrays.fill(msg, (byte) 99);
        strobe.ad(msg, false);

        System.out.println(strobe);
    }
}
