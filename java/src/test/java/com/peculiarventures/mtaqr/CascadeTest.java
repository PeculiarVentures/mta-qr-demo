package com.peculiarventures.mtaqr;

import com.peculiarventures.mtaqr.cascade.Cascade;
import org.junit.jupiter.api.Test;
import java.util.HexFormat;
import static org.junit.jupiter.api.Assertions.*;

class CascadeTest {

    private static final String R1_HEX = "01000000080112";
    private static final long[] R1_REVOKED = {2L, 5L};
    private static final long[] R1_VALID   = {1L, 3L, 4L, 6L, 7L, 8L};

    private static byte[] fromHex(String s) { return HexFormat.of().parseHex(s); }
    private static String hex(byte[] b)     { return HexFormat.of().formatHex(b); }

    @Test void r1Queries() {
        var c = Cascade.build(R1_REVOKED, R1_VALID);
        assertFalse(c.query(0)); assertFalse(c.query(1));
        assertTrue (c.query(2)); assertFalse(c.query(3));
        assertFalse(c.query(4)); assertTrue (c.query(5));
        assertFalse(c.query(6)); assertFalse(c.query(7));
        assertFalse(c.query(8)); assertFalse(c.query(99));
    }

    @Test void r1LockedBytes() {
        assertEquals(R1_HEX, hex(Cascade.build(R1_REVOKED, R1_VALID).encode()),
            "R1 bytes changed — update spec and all cross-language vectors");
    }

    @Test void r1RoundTrip() {
        var c  = Cascade.build(R1_REVOKED, R1_VALID);
        var c2 = Cascade.decode(fromHex(R1_HEX));
        for (long x : new long[]{1,2,3,4,5,6,7,8,99})
            assertEquals(c.query(x), c2.query(x), "mismatch at " + x);
    }

    @Test void r2Empty() {
        var c = Cascade.build(new long[0], new long[]{1,2,3});
        assertArrayEquals(new byte[]{0}, c.encode());
        assertFalse(c.query(1)); assertFalse(c.query(99));
    }

    @Test void rejectTruncatedHeader() {
        assertThrows(IllegalArgumentException.class,
            () -> Cascade.decode(new byte[]{1, 0, 0, 0}));
    }

    @Test void rejectBitCountZero() {
        assertThrows(IllegalArgumentException.class,
            () -> Cascade.decode(new byte[]{1, 0, 0, 0, 0, 1}));
    }

    @Test void rejectKNotOne() {
        assertThrows(IllegalArgumentException.class,
            () -> Cascade.decode(new byte[]{1, 0, 0, 0, 8, 2, 0}));
    }

    @Test void rejectTruncatedBits() {
        assertThrows(IllegalArgumentException.class,
            () -> Cascade.decode(new byte[]{1, 0, 0, 0, 8, 1}));
    }

    @Test void rejectTrailingBytes() {
        assertThrows(IllegalArgumentException.class,
            () -> Cascade.decode(new byte[]{0, (byte)0xff}));
    }

    @Test void determinism() {
        long[] r = {10, 20, 30};
        long[] s = {1, 2, 3, 4, 5, 6, 7, 8, 9, 11};
        assertArrayEquals(Cascade.build(r, s).encode(), Cascade.build(r, s).encode());
    }
}
