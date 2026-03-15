package com.peculiarventures.mtaqr;

import org.bouncycastle.pqc.crypto.crystals.dilithium.*;
import org.junit.jupiter.api.Test;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HexFormat;

public class ProbeTest {

    static byte[] keygenFromXi(byte[] xi) throws Exception {
        // Feed xi directly as the 32-byte RNG output — one call, exact bytes
        SecureRandom exact = new SecureRandom() {
            boolean consumed = false;
            @Override public void nextBytes(byte[] bytes) {
                if (consumed || bytes.length != 32)
                    throw new RuntimeException("Unexpected RNG call: len=" + bytes.length + " consumed=" + consumed);
                System.arraycopy(xi, 0, bytes, 0, 32);
                consumed = true;
            }
        };
        DilithiumKeyPairGenerator gen = new DilithiumKeyPairGenerator();
        gen.init(new DilithiumKeyGenerationParameters(exact, DilithiumParameters.dilithium2));
        var kp = gen.generateKeyPair();
        return ((DilithiumPublicKeyParameters) kp.getPublic()).getEncoded();
    }

    @Test
    public void probeWithActualInteropSeed() throws Exception {
        // The seed used in interop tests
        byte[] seed = MessageDigest.getInstance("SHA-256").digest("interop-ml-dsa-44".getBytes());

        System.out.println("seed: " + HexFormat.of().formatHex(seed));

        // What TS/Go/Rust produce from this seed (from trust config)
        String tsPrefix = "07a29e160abfac0f";
        System.out.println("TS/Go/Rust pubkey prefix: " + tsPrefix + "...");

        // What BC produces if fed seed directly as xi
        byte[] bcPub = keygenFromXi(seed);
        System.out.println("BC pubkey prefix:         " + HexFormat.of().formatHex(bcPub).substring(0, 16) + "...");
        System.out.println("Match: " + HexFormat.of().formatHex(bcPub).startsWith(tsPrefix));
    }

    @Test 
    public void probeOldFixedSecureRandom() throws Exception {
        byte[] seed = MessageDigest.getInstance("SHA-256").digest("interop-ml-dsa-44".getBytes());

        // Simulate what our FixedSecureRandom did — cycles through seed bytes
        byte[] cycledXi = new byte[32];
        for (int i = 0; i < 32; i++) cycledXi[i] = seed[i % seed.length]; // same as seed itself since len=32
        
        System.out.println("seed len: " + seed.length);
        System.out.println("cycled == seed: " + java.util.Arrays.equals(seed, cycledXi));

        // So FixedSecureRandom with a 32-byte seed requesting 32 bytes
        // gives exactly seed[0..31] — identical to direct xi passthrough
        // The bug must be elsewhere. Let's check what FixedSecureRandom actually does
        // when the generator makes multiple reads of smaller sizes internally
        
        int[] callSizes = new int[50];
        int[] callCount = {0};
        int[] pos = {0};

        SecureRandom fixed = new SecureRandom() {
            @Override public void nextBytes(byte[] bytes) {
                callSizes[callCount[0]] = bytes.length;
                for (int i = 0; i < bytes.length; i++) {
                    bytes[i] = seed[pos[0] % seed.length];
                    pos[0]++;
                }
                callCount[0]++;
            }
        };
        
        DilithiumKeyPairGenerator gen = new DilithiumKeyPairGenerator();
        gen.init(new DilithiumKeyGenerationParameters(fixed, DilithiumParameters.dilithium2));
        var kp = gen.generateKeyPair();

        System.out.println("\nWith FixedSecureRandom (cycling):");
        System.out.println("  RNG calls: " + callCount[0]);
        System.out.println("  Total bytes: " + pos[0]);
        for (int i = 0; i < callCount[0]; i++)
            System.out.println("  call " + i + ": " + callSizes[i] + " bytes");

        var pub = (DilithiumPublicKeyParameters) kp.getPublic();
        byte[] pubBytes = pub.getEncoded();
        System.out.println("  pubkey prefix: " + HexFormat.of().formatHex(pubBytes).substring(0, 16));

        // Now compare with direct xi passthrough
        byte[] directPub = keygenFromXi(seed);
        System.out.println("  direct xi prefix: " + HexFormat.of().formatHex(directPub).substring(0, 16));
        System.out.println("  same key: " + java.util.Arrays.equals(pubBytes, directPub));
    }
}
