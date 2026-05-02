package org.example;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Autorska implementacja algorytmu DSA (Digital Signature Algorithm).
 *
 * Parametry domyślne: L=1024 (p), N=160 (q) — zgodne z FIPS 186-2.
 * Opcjonalnie: L=2048, N=256 — zgodne z FIPS 186-4.
 *
 * UWAGA: Implementacja edukacyjna; nie stosować w środowiskach produkcyjnych.
 */
public class DSAwlasny {

    // -----------------------------------------------------------------------
    // KLASA KLUCZY
    // -----------------------------------------------------------------------

    public static class DSAKeyPair {
        public final BigInteger p;   // liczba pierwsza (L bitów)
        public final BigInteger q;   // liczba pierwsza (N bitów), q | (p-1)
        public final BigInteger g;   // generator grupy cyklicznej
        public final BigInteger x;   // klucz prywatny: x ∈ (0, q)
        public final BigInteger y;   // klucz publiczny: y = g^x mod p

        public DSAKeyPair(BigInteger p, BigInteger q, BigInteger g,
                          BigInteger x, BigInteger y) {
            this.p = p; this.q = q; this.g = g;
            this.x = x; this.y = y;
        }

        /** Zwraca publiczną część pary kluczy (bez x). */
        public DSAPublicKey getPublicKey() {
            return new DSAPublicKey(p, q, g, y);
        }
    }

    public static class DSAPublicKey {
        public final BigInteger p, q, g, y;
        public DSAPublicKey(BigInteger p, BigInteger q, BigInteger g, BigInteger y) {
            this.p = p; this.q = q; this.g = g; this.y = y;
        }
    }

    public static class DSASignature {
        public final BigInteger r;
        public final BigInteger s;
        public DSASignature(BigInteger r, BigInteger s) {
            this.r = r; this.s = s;
        }

        @Override
        public String toString() {
            return "r=" + r.toString(16).toUpperCase() + "\n" +
                    "s=" + s.toString(16).toUpperCase();
        }
    }

    // -----------------------------------------------------------------------
    // PARAMETRY
    // -----------------------------------------------------------------------

    private final int L;   // długość p w bitach
    private final int N;   // długość q w bitach
    private final SecureRandom rng = new SecureRandom();

    public DSAwlasny() {
        this(1024, 160);
    }

    public DSAwlasny(int L, int N) {
        if (!((L == 1024 && N == 160) || (L == 2048 && N == 256))) {
            throw new IllegalArgumentException("Obsługiwane pary (L,N): (1024,160) lub (2048,256).");
        }
        this.L = L;
        this.N = N;
    }

    // -----------------------------------------------------------------------
    // GENEROWANIE PARAMETRÓW DOMENOWYCH (p, q, g)
    // -----------------------------------------------------------------------

    /**
     * Generuje parametry domenowe DSA:
     *   1. q — N-bitowa liczba pierwsza
     *   2. p — L-bitowa liczba pierwsza taka, że q | (p-1)
     *   3. g — generator rzędu q w Z*_p
     */
    public BigInteger[] generateDomainParameters() {
        BigInteger q = generateSafePrime(N);
        BigInteger p = generatePWithFactor(q, L);
        BigInteger g = generateGenerator(p, q);
        return new BigInteger[]{p, q, g};
    }

    /**
     * Generuje N-bitową liczbę pierwszą q.
     */
    private BigInteger generateSafePrime(int bits) {
        BigInteger q;
        do {
            q = BigInteger.probablePrime(bits, rng);
        } while (q.bitLength() != bits);
        return q;
    }

    /**
     * Szuka L-bitowej liczby pierwszej p takiej, że p ≡ 1 (mod q).
     * Konstrukcja: p = k*q + 1 dla losowego k; sprawdza pierwszość p.
     */
    private BigInteger generatePWithFactor(BigInteger q, int bits) {
        BigInteger p;
        BigInteger TWO = BigInteger.TWO;
        // k musi być parzyste, by p = k*q+1 mogło być nieparzyste (q jest nieparzyste > 2)
        // Szukamy k ≈ 2^(L-1) / q
        int kBits = bits - N;
        do {
            BigInteger k = new BigInteger(kBits, rng).setBit(kBits - 1); // k ma kBits bitów
            // zaokrąglij k do parzystego
            if (k.testBit(0)) k = k.add(BigInteger.ONE);
            p = k.multiply(q).add(BigInteger.ONE);
        } while (p.bitLength() != bits || !p.isProbablePrime(80));
        return p;
    }

    /**
     * Wybiera generator g rzędu q w Z*_p.
     * Metoda: dla losowego h ∈ (1, p-1) oblicza g = h^((p-1)/q) mod p;
     * jeśli g ≠ 1, to g ma rząd q.
     */
    private BigInteger generateGenerator(BigInteger p, BigInteger q) {
        BigInteger pMinus1 = p.subtract(BigInteger.ONE);
        BigInteger exp = pMinus1.divide(q);
        BigInteger g;
        do {
            BigInteger h = randomInRange(BigInteger.TWO, pMinus1);
            g = h.modPow(exp, p);
        } while (g.equals(BigInteger.ONE));
        return g;
    }

    // -----------------------------------------------------------------------
    // GENEROWANIE KLUCZY
    // -----------------------------------------------------------------------

    /**
     * Generuje parę kluczy DSA na podstawie podanych parametrów domenowych.
     * Klucz prywatny x ∈ (0, q), klucz publiczny y = g^x mod p.
     */
    public DSAKeyPair generateKeyPair(BigInteger p, BigInteger q, BigInteger g) {
        BigInteger x = randomInRange(BigInteger.ONE, q.subtract(BigInteger.ONE));
        BigInteger y = g.modPow(x, p);
        return new DSAKeyPair(p, q, g, x, y);
    }

    /**
     * Generuje parę kluczy (wraz z parametrami domenowymi) — wygodna metoda all-in-one.
     */
    public DSAKeyPair generateKeyPair() {
        BigInteger[] params = generateDomainParameters();
        return generateKeyPair(params[0], params[1], params[2]);
    }

    // -----------------------------------------------------------------------
    // PODPISYWANIE
    // -----------------------------------------------------------------------

    /**
     * Podpisuje dane (wiadomość) przy użyciu klucza prywatnego x.
     *
     * Algorytm:
     *   1. Oblicz H = hash(M) — używamy SHA-1 (N=160) lub SHA-256 (N=256)
     *   2. Wybierz losowe k ∈ (0, q)
     *   3. r = (g^k mod p) mod q; jeśli r=0, wróć do 2
     *   4. s = k^-1 * (H + x*r) mod q; jeśli s=0, wróć do 2
     *   5. Podpis = (r, s)
     *
     * @param data    dane do podpisania (dowolna długość)
     * @param keyPair para kluczy (używany klucz prywatny x)
     * @return podpis DSA (r, s)
     */
    public DSASignature sign(byte[] data, DSAKeyPair keyPair) {
        byte[] hash = hash(data);
        BigInteger H = new BigInteger(1, truncateHash(hash, N));

        BigInteger p = keyPair.p, q = keyPair.q, g = keyPair.g, x = keyPair.x;
        BigInteger r, s, k;

        do {
            do {
                k = randomInRange(BigInteger.ONE, q.subtract(BigInteger.ONE));
                r = g.modPow(k, p).mod(q);
            } while (r.equals(BigInteger.ZERO));

            BigInteger kInv = k.modInverse(q);
            s = kInv.multiply(H.add(x.multiply(r))).mod(q);
        } while (s.equals(BigInteger.ZERO));

        return new DSASignature(r, s);
    }

    // -----------------------------------------------------------------------
    // WERYFIKACJA
    // -----------------------------------------------------------------------

    /**
     * Weryfikuje podpis DSA.
     *
     * Algorytm:
     *   1. Sprawdź: 0 < r < q oraz 0 < s < q
     *   2. w = s^-1 mod q
     *   3. u1 = H*w mod q
     *   4. u2 = r*w mod q
     *   5. v = (g^u1 * y^u2 mod p) mod q
     *   6. Podpis jest prawidłowy ⟺ v == r
     *
     * @param data      oryginalne dane (niezmienione)
     * @param signature podpis do weryfikacji
     * @param publicKey klucz publiczny nadawcy
     * @return true jeśli podpis jest prawidłowy
     */
    public boolean verify(byte[] data, DSASignature signature, DSAPublicKey publicKey) {
        BigInteger r = signature.r, s = signature.s;
        BigInteger p = publicKey.p, q = publicKey.q;
        BigInteger g = publicKey.g, y = publicKey.y;

        // Weryfikacja zakresu
        if (r.compareTo(BigInteger.ZERO) <= 0 || r.compareTo(q) >= 0) return false;
        if (s.compareTo(BigInteger.ZERO) <= 0 || s.compareTo(q) >= 0) return false;

        byte[] hash = hash(data);
        BigInteger H = new BigInteger(1, truncateHash(hash, N));

        BigInteger w  = s.modInverse(q);
        BigInteger u1 = H.multiply(w).mod(q);
        BigInteger u2 = r.multiply(w).mod(q);

        BigInteger v = g.modPow(u1, p)
                .multiply(y.modPow(u2, p))
                .mod(p)
                .mod(q);

        return v.equals(r);
    }

    // -----------------------------------------------------------------------
    // SERIALIZACJA / DESERIALIZACJA KLUCZA (format tekstowy Base16)
    // -----------------------------------------------------------------------

    /**
     * Eksportuje parę kluczy do formatu tekstowego (hex, separator ":").
     * Format: p:q:g:x:y
     */
    public static String exportKeyPair(DSAKeyPair kp) {
        return kp.p.toString(16) + ":" +
                kp.q.toString(16) + ":" +
                kp.g.toString(16) + ":" +
                kp.x.toString(16) + ":" +
                kp.y.toString(16);
    }

    /**
     * Eksportuje klucz publiczny do formatu tekstowego.
     * Format: p:q:g:y
     */
    public static String exportPublicKey(DSAPublicKey pk) {
        return pk.p.toString(16) + ":" +
                pk.q.toString(16) + ":" +
                pk.g.toString(16) + ":" +
                pk.y.toString(16);
    }

    /** Importuje pełną parę kluczy z formatu p:q:g:x:y */
    public static DSAKeyPair importKeyPair(String s) {
        String[] parts = s.trim().split(":");
        if (parts.length != 5) throw new IllegalArgumentException("Oczekiwano 5 elementów (p:q:g:x:y).");
        BigInteger p = new BigInteger(parts[0], 16);
        BigInteger q = new BigInteger(parts[1], 16);
        BigInteger g = new BigInteger(parts[2], 16);
        BigInteger x = new BigInteger(parts[3], 16);
        BigInteger y = new BigInteger(parts[4], 16);
        return new DSAKeyPair(p, q, g, x, y);
    }

    /** Importuje klucz publiczny z formatu p:q:g:y */
    public static DSAPublicKey importPublicKey(String s) {
        String[] parts = s.trim().split(":");
        if (parts.length != 4) throw new IllegalArgumentException("Oczekiwano 4 elementów (p:q:g:y).");
        BigInteger p = new BigInteger(parts[0], 16);
        BigInteger q = new BigInteger(parts[1], 16);
        BigInteger g = new BigInteger(parts[2], 16);
        BigInteger y = new BigInteger(parts[3], 16);
        return new DSAPublicKey(p, q, g, y);
    }

    /** Serializuje podpis do stringa: r:s (hex) */
    public static String exportSignature(DSASignature sig) {
        return sig.r.toString(16) + ":" + sig.s.toString(16);
    }

    /** Deserializuje podpis ze stringa r:s (hex) */
    public static DSASignature importSignature(String s) {
        String[] parts = s.trim().split(":");
        if (parts.length != 2) throw new IllegalArgumentException("Oczekiwano 2 elementów (r:s).");
        return new DSASignature(new BigInteger(parts[0], 16), new BigInteger(parts[1], 16));
    }

    // -----------------------------------------------------------------------
    // HELPERS
    // -----------------------------------------------------------------------

    private byte[] hash(byte[] data) {
        try {
            String alg = (N == 160) ? "SHA-1" : "SHA-256";
            return MessageDigest.getInstance(alg).digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Algorytm haszowania niedostępny.", e);
        }
    }

    /**
     * Skraca hash do N bitów (lewe N bitów) — zgodnie z FIPS 186-4 sekcja 4.6.
     */
    private byte[] truncateHash(byte[] hash, int nBits) {
        int nBytes = (nBits + 7) / 8;
        if (hash.length <= nBytes) return hash;
        byte[] out = new byte[nBytes];
        System.arraycopy(hash, 0, out, 0, nBytes);
        return out;
    }

    /** Losuje BigInteger z przedziału [min, max] włącznie. */
    private BigInteger randomInRange(BigInteger min, BigInteger max) {
        BigInteger range = max.subtract(min).add(BigInteger.ONE);
        int bits = range.bitLength();
        BigInteger r;
        do {
            r = new BigInteger(bits, rng);
        } while (r.compareTo(range) >= 0);
        return r.add(min);
    }
}