package org.example;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Autorska implementacja algorytmu AES-128 w trybie ECB z paddingiem PKCS5.
 */
public class AESwlasny {

    private static final int[] sBox = {
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };

    private static final int[] rsBox = {
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };

    private static final int[] rCon = {
            0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    };

    // -----------------------------------------------------------------------
    // PUBLIC API
    // -----------------------------------------------------------------------

    /** Generuje losowy klucz 128-bitowy (16 bajtów) zakodowany nie — zwraca surowe bajty. */
    public byte[] generowanieklucza() {
        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);
        return key;
    }

    /**
     * Szyfruje dane z użyciem paddingu PKCS5.
     *
     * @param data     dane wejściowe (dowolna długość)
     * @param keyBytes klucz 16-bajtowy
     * @return zaszyfrowane dane
     * @throws IllegalArgumentException gdy klucz ma złą długość
     */
    public byte[] encrypt(byte[] data, byte[] keyBytes) {
        validateKey(keyBytes);
        byte[] paddedData = addPadding(data);
        return processECB(paddedData, keyBytes, true);
    }

    /**
     * Odszyfrowuje dane i usuwa padding PKCS5.
     *
     * @param encryptedData zaszyfrowane dane (długość musi być wielokrotnością 16)
     * @param keyBytes      klucz 16-bajtowy
     * @return odszyfrowane dane bez paddingu
     * @throws IllegalArgumentException gdy klucz lub dane mają złą długość
     * @throws IllegalStateException    gdy padding jest nieprawidłowy (zły klucz lub uszkodzone dane)
     */
    public byte[] decrypt(byte[] encryptedData, byte[] keyBytes) {
        validateKey(keyBytes);
        if (encryptedData.length == 0 || encryptedData.length % 16 != 0) {
            throw new IllegalArgumentException(
                    "Dane do odszyfrowania muszą być niepuste i wielokrotnością 16 bajtów.");
        }
        byte[] decryptedPadded = processECB(encryptedData, keyBytes, false);
        return removePadding(decryptedPadded);
    }

    // -----------------------------------------------------------------------
    // WALIDACJA
    // -----------------------------------------------------------------------

    private void validateKey(byte[] keyBytes) {
        if (keyBytes == null || keyBytes.length != 16) {
            throw new IllegalArgumentException(
                    "Klucz AES-128 musi mieć dokładnie 16 bajtów (128 bitów). " +
                            "Otrzymano: " + (keyBytes == null ? "null" : keyBytes.length + " bajtów"));
        }
    }

    // -----------------------------------------------------------------------
    // ECB
    // -----------------------------------------------------------------------

    private byte[] processECB(byte[] data, byte[] keyBytes, boolean encrypt) {
        int[] expandedKey = expandKey(keyBytes);
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i += 16) {
            byte[] block = Arrays.copyOfRange(data, i, i + 16);
            byte[] processed = encrypt
                    ? encryptBlock(block, expandedKey)
                    : decryptBlock(block, expandedKey);
            System.arraycopy(processed, 0, result, i, 16);
        }
        return result;
    }

    // -----------------------------------------------------------------------
    // PADDING PKCS5 (identyczny z PKCS7 dla bloków 16-bajtowych)
    // -----------------------------------------------------------------------

    private byte[] addPadding(byte[] data) {
        // paddingLen wynosi zawsze 1–16, więc nawet dane będące wielokrotnością 16
        // dostają pełny blok paddingu — umożliwia to pewne usunięcie paddingu.
        int paddingLen = 16 - (data.length % 16);
        byte[] padded = Arrays.copyOf(data, data.length + paddingLen);
        Arrays.fill(padded, data.length, padded.length, (byte) paddingLen);
        return padded;
    }

    /**
     * Usuwa i weryfikuje padding PKCS5.
     * Rzuca wyjątek gdy padding jest nieprawidłowy (np. użyto złego klucza).
     */
    private byte[] removePadding(byte[] data) {
        if (data.length == 0) {
            throw new IllegalStateException("Odszyfrowane dane są puste — prawdopodobnie błędny klucz.");
        }
        int paddingLen = data[data.length - 1] & 0xFF;

        if (paddingLen < 1 || paddingLen > 16) {
            throw new IllegalStateException(
                    "Nieprawidłowy padding (wartość " + paddingLen + ") — błędny klucz lub uszkodzone dane.");
        }

        for (int i = data.length - paddingLen; i < data.length; i++) {
            if ((data[i] & 0xFF) != paddingLen) {
                throw new IllegalStateException(
                        "Nieprawidłowy padding PKCS5 — błędny klucz lub uszkodzone dane.");
            }
        }

        return Arrays.copyOfRange(data, 0, data.length - paddingLen);
    }

    // -----------------------------------------------------------------------
    // KEY EXPANSION
    // -----------------------------------------------------------------------

    private int[] expandKey(byte[] key) {
        final int nk = 4;   // liczba słów w kluczu (128 bit → 4)
        final int nr = 10;  // liczba rund AES-128
        int[] w = new int[4 * (nr + 1)];

        for (int i = 0; i < nk; i++) {
            w[i] = ((key[4 * i]     & 0xFF) << 24)
                    | ((key[4 * i + 1] & 0xFF) << 16)
                    | ((key[4 * i + 2] & 0xFF) <<  8)
                    |  (key[4 * i + 3] & 0xFF);
        }

        for (int i = nk; i < w.length; i++) {
            int temp = w[i - 1];
            if (i % nk == 0) {
                // rCon indeksowany od 1 do nr — celowe, zgodne ze specyfikacją AES
                temp = subWord(rotWord(temp)) ^ (rCon[i / nk] << 24);
            }
            w[i] = w[i - nk] ^ temp;
        }
        return w;
    }

    private int rotWord(int word) {
        return (word << 8) | (word >>> 24);
    }

    private int subWord(int word) {
        return (sBox[(word >>> 24) & 0xFF] << 24)
                | (sBox[(word >>> 16) & 0xFF] << 16)
                | (sBox[(word >>>  8) & 0xFF] <<  8)
                |  sBox[ word         & 0xFF];
    }

    // -----------------------------------------------------------------------
    // SZYFROWANIE / DESZYFROWANIE BLOKU
    // -----------------------------------------------------------------------

    private byte[] encryptBlock(byte[] block, int[] w) {
        int[][] state = bytesToState(block);
        addRoundKey(state, w, 0);

        for (int round = 1; round < 10; round++) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, w, round);
        }

        // Ostatnia runda — bez MixColumns
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, w, 10);
        return stateToBytes(state);
    }

    private byte[] decryptBlock(byte[] block, int[] w) {
        int[][] state = bytesToState(block);
        addRoundKey(state, w, 10);

        for (int round = 9; round >= 1; round--) {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, w, round);
            invMixColumns(state);
        }

        // Pierwsza runda odwrotna — bez InvMixColumns
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, w, 0);
        return stateToBytes(state);
    }

    // -----------------------------------------------------------------------
    // STATE ↔ BYTES
    // -----------------------------------------------------------------------

    private int[][] bytesToState(byte[] b) {
        int[][] s = new int[4][4];
        for (int i = 0; i < 16; i++) {
            s[i % 4][i / 4] = b[i] & 0xFF;
        }
        return s;
    }

    private byte[] stateToBytes(int[][] s) {
        byte[] b = new byte[16];
        for (int i = 0; i < 16; i++) {
            b[i] = (byte) s[i % 4][i / 4];
        }
        return b;
    }

    // -----------------------------------------------------------------------
    // TRANSFORMACJE AES
    // -----------------------------------------------------------------------

    private void addRoundKey(int[][] s, int[] w, int round) {
        for (int c = 0; c < 4; c++) {
            int word = w[round * 4 + c];
            s[0][c] ^= (word >>> 24) & 0xFF;
            s[1][c] ^= (word >>> 16) & 0xFF;
            s[2][c] ^= (word >>>  8) & 0xFF;
            s[3][c] ^=  word & 0xFF;
        }
    }

    private void subBytes(int[][] s) {
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
                s[r][c] = sBox[s[r][c]];
    }

    private void invSubBytes(int[][] s) {
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
                s[r][c] = rsBox[s[r][c]];
    }

    private void shiftRows(int[][] s) {
        for (int r = 1; r < 4; r++) {
            int[] t = new int[4];
            for (int c = 0; c < 4; c++) t[c] = s[r][(c + r) % 4];
            System.arraycopy(t, 0, s[r], 0, 4);
        }
    }

    private void invShiftRows(int[][] s) {
        for (int r = 1; r < 4; r++) {
            int[] t = new int[4];
            for (int c = 0; c < 4; c++) t[(c + r) % 4] = s[r][c];
            System.arraycopy(t, 0, s[r], 0, 4);
        }
    }

    private void mixColumns(int[][] s) {
        for (int c = 0; c < 4; c++) {
            int a0 = s[0][c], a1 = s[1][c], a2 = s[2][c], a3 = s[3][c];
            s[0][c] = gfMul(2, a0) ^ gfMul(3, a1) ^ a2          ^ a3;
            s[1][c] = a0           ^ gfMul(2, a1) ^ gfMul(3, a2) ^ a3;
            s[2][c] = a0           ^ a1           ^ gfMul(2, a2) ^ gfMul(3, a3);
            s[3][c] = gfMul(3, a0) ^ a1           ^ a2           ^ gfMul(2, a3);
        }
    }

    private void invMixColumns(int[][] s) {
        for (int c = 0; c < 4; c++) {
            int a0 = s[0][c], a1 = s[1][c], a2 = s[2][c], a3 = s[3][c];
            s[0][c] = gfMul(14, a0) ^ gfMul(11, a1) ^ gfMul(13, a2) ^ gfMul( 9, a3);
            s[1][c] = gfMul( 9, a0) ^ gfMul(14, a1) ^ gfMul(11, a2) ^ gfMul(13, a3);
            s[2][c] = gfMul(13, a0) ^ gfMul( 9, a1) ^ gfMul(14, a2) ^ gfMul(11, a3);
            s[3][c] = gfMul(11, a0) ^ gfMul(13, a1) ^ gfMul( 9, a2) ^ gfMul(14, a3);
        }
    }

    /**
     * Mnożenie w GF(2^8) z wielomianem redukcyjnym x^8 + x^4 + x^3 + x + 1 (0x11B).
     * Przemianowane z g() na gfMul() dla czytelności.
     */
    private int gfMul(int a, int b) {
        int p = 0;
        for (int i = 0; i < 8; i++) {
            if ((b & 1) != 0) p ^= a;
            boolean hiBitSet = (a & 0x80) != 0;
            a = (a << 1) & 0xFF;
            if (hiBitSet) a ^= 0x1B;
            b >>= 1;
        }
        return p & 0xFF;
    }
}
