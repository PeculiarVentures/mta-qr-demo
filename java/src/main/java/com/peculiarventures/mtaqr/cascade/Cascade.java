package com.peculiarventures.mtaqr.cascade;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * MTA-QR Bloom filter cascade for revocation.
 * SPEC.md §Revocation — Normative Construction Parameters.
 */
public class Cascade {

    private static final double BITS_PER_ELEMENT = 1.4427;
    private static final int    MIN_FILTER_BITS  = 8;
    private static final int    MAX_LEVELS       = 32;

    private final int[]    bitCounts;
    private final byte[][] bits;

    private Cascade(int[] bitCounts, byte[][] bits) {
        this.bitCounts = bitCounts;
        this.bits      = bits;
    }

    public static Cascade build(long[] revoked, long[] valid) {
        if (revoked == null || revoked.length == 0)
            return new Cascade(new int[0], new byte[0][]);

        long[] include = sorted(revoked);
        long[] exclude = sorted(valid != null ? valid : new long[0]);

        List<Integer> bcList   = new ArrayList<>();
        List<byte[]>  bitsList = new ArrayList<>();

        for (int li = 0; li < MAX_LEVELS; li++) {
            if (include.length == 0) break;
            int m = filterSize(include.length);
            byte[] levelBits = new byte[m / 8];

            for (long x : include) {
                int b = bitPosition(x, li, m);
                levelBits[b / 8] |= (byte)(1 << (7 - (b % 8)));
            }
            bcList.add(m);
            bitsList.add(levelBits);

            List<Long> fp = new ArrayList<>();
            for (long x : exclude) {
                int b = bitPosition(x, li, m);
                if (((levelBits[b / 8] >> (7 - (b % 8))) & 1) == 1) fp.add(x);
            }

            long[] newInclude = fp.stream().mapToLong(Long::longValue).toArray();
            exclude = include;
            include = newInclude;
        }

        if (include.length != 0)
            throw new IllegalStateException("cascade: did not terminate within " + MAX_LEVELS + " levels");

        int[] bc   = bcList.stream().mapToInt(Integer::intValue).toArray();
        byte[][] b = bitsList.toArray(new byte[0][]);
        return new Cascade(bc, b);
    }

    public boolean query(long x) {
        if (bitCounts.length == 0) return false;
        boolean result = false;
        for (int i = 0; i < bitCounts.length; i++) {
            int b = bitPosition(x, i, bitCounts[i]);
            boolean inFilter = ((bits[i][b / 8] >> (7 - (b % 8))) & 1) == 1;
            if (i == 0) {
                if (!inFilter) return false;
                result = true;
            } else {
                if (inFilter) result = !result;
                else          return result;
            }
        }
        return result;
    }

    public byte[] encode() {
        int total = 1;
        for (int i = 0; i < bitCounts.length; i++) total += 5 + bits[i].length;
        byte[] out = new byte[total];
        out[0] = (byte) bitCounts.length;
        int pos = 1;
        for (int i = 0; i < bitCounts.length; i++) {
            ByteBuffer.wrap(out, pos, 4).putInt(bitCounts[i]);
            out[pos + 4] = 1;
            pos += 5;
            System.arraycopy(bits[i], 0, out, pos, bits[i].length);
            pos += bits[i].length;
        }
        return out;
    }

    public static Cascade decode(byte[] b) {
        if (b == null || b.length == 0) throw new IllegalArgumentException("cascade: empty input");
        int numLevels = b[0] & 0xff;
        int pos = 1;
        int[] bc   = new int[numLevels];
        byte[][] lb = new byte[numLevels][];
        for (int i = 0; i < numLevels; i++) {
            if (pos + 5 > b.length) throw new IllegalArgumentException("cascade: truncated at level " + i + " header");
            int bitCount = ByteBuffer.wrap(b, pos, 4).getInt();
            int k = b[pos + 4] & 0xff;
            pos += 5;
            if (k != 1) throw new IllegalArgumentException("cascade: level " + i + " has k=" + k + ", MUST be 1");
            if (bitCount == 0) throw new IllegalArgumentException("cascade: level " + i + " has bit_count=0");
            int byteCount = (bitCount + 7) / 8;
            if (pos + byteCount > b.length) throw new IllegalArgumentException("cascade: truncated at level " + i + " bit array");
            bc[i] = bitCount;
            lb[i] = Arrays.copyOfRange(b, pos, pos + byteCount);
            pos += byteCount;
        }
        if (pos != b.length) throw new IllegalArgumentException("cascade: " + (b.length - pos) + " trailing bytes");
        return new Cascade(bc, lb);
    }

    private static int bitPosition(long x, int li, int m) {
        try {
            byte[] buf = new byte[9];
            ByteBuffer.wrap(buf).putLong(x);
            buf[8] = (byte) li;
            byte[] h = MessageDigest.getInstance("SHA-256").digest(buf);
            long v = ByteBuffer.wrap(h, 0, 8).getLong();
            return (int) Long.remainderUnsigned(v, m);
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    private static int filterSize(int n) {
        int m = Math.max((int) Math.ceil(n * BITS_PER_ELEMENT), MIN_FILTER_BITS);
        return (m + 7) & ~7;
    }

    private static long[] sorted(long[] a) {
        long[] c = Arrays.copyOf(a, a.length);
        Arrays.sort(c);
        return c;
    }
}
