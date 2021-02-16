/*
 * Copyright (c) 2021 acmi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package acmi.l2.clientmod.crypt;

import acmi.l2.clientmod.crypt.blowfish.L2Ver21xInputStream;
import acmi.l2.clientmod.crypt.blowfish.L2Ver21xOutputStream;
import acmi.l2.clientmod.crypt.lame.LameCrypt;
import acmi.l2.clientmod.crypt.rsa.L2Ver41xInputStream;
import acmi.l2.clientmod.crypt.rsa.L2Ver41xOutputStream;
import acmi.l2.clientmod.crypt.xor.L2Ver120InputStream;
import acmi.l2.clientmod.crypt.xor.L2Ver120OutputStream;
import acmi.l2.clientmod.crypt.xor.L2Ver1x1InputStream;
import acmi.l2.clientmod.crypt.xor.L2Ver1x1OutputStream;

import java.io.*;
import java.math.BigInteger;

import static acmi.l2.clientmod.crypt.blowfish.L2Ver21x.BLOWFISH_KEY_211;
import static acmi.l2.clientmod.crypt.blowfish.L2Ver21x.BLOWFISH_KEY_212;
import static acmi.l2.clientmod.crypt.rsa.L2Ver41x.*;
import static acmi.l2.clientmod.crypt.xor.L2Ver1x1.XOR_KEY_111;
import static acmi.l2.clientmod.crypt.xor.L2Ver1x1.getXORKey121;
import static java.nio.charset.StandardCharsets.UTF_16LE;

public class L2Crypt {
    public static final int NO_CRYPT = -1;

    private static final BigInteger[][] RSA_KEYS = new BigInteger[][]{
            {MODULUS_411, PRIVATE_EXPONENT_411},
            {MODULUS_412, PRIVATE_EXPONENT_412},
            {MODULUS_413, PRIVATE_EXPONENT_413},
            {MODULUS_414, PRIVATE_EXPONENT_414}
    };
    private static BigInteger publicModulus = MODULUS_L2ENCDEC;
    private static BigInteger publicExponent = PUBLIC_EXPONENT_L2ENCDEC;

    public static void set41xPrivateKey(int version, BigInteger modulus, BigInteger exponent) {
        RSA_KEYS[version - 411][0] = modulus;
        RSA_KEYS[version - 411][1] = exponent;
    }

    public static void set41xPublicKey(BigInteger publicModulus, BigInteger publicExponent) {
        L2Crypt.publicModulus = publicModulus;
        L2Crypt.publicExponent = publicExponent;
    }

    public static final int HEADER_SIZE = 28;

    public static int readHeader(InputStream input) throws IOException {
        byte[] header = new byte[HEADER_SIZE];
        new DataInputStream(input).readFully(header);
        String headerStr = new String(header, UTF_16LE);
        if (!headerStr.matches("Lineage2Ver\\d{3}")) {
            return NO_CRYPT;
        }

        return Integer.parseInt(headerStr.substring(11));
    }

    public static void writeHeader(OutputStream output, int version) throws IOException {
        output.write(("Lineage2Ver" + version).getBytes(UTF_16LE));
    }

    public static InputStream getInputStream(File file) throws IOException, CryptoException {
        return decrypt(new FileInputStream(file), file.getName());
    }

    public static InputStream decrypt(InputStream input, String fileName) throws IOException, CryptoException {
        int version = readHeader(input);
        switch (version) {
            case NO_CRYPT:
                return input;
            //XOR
            case 811:
            case 821:
                input = LameCrypt.wrapInput(input);
                version -= 700;
            case 111:
            case 121:
                return new L2Ver1x1InputStream(input, version == 111 ?
                        XOR_KEY_111 :
                        getXORKey121(fileName));
            case 820:
                input = LameCrypt.wrapInput(input);
            case 120:
                return new L2Ver120InputStream(input);
            //BLOWFISH
            case 911:
            case 912:
                input = LameCrypt.wrapInput(input);
                version -= 700;
            case 211:
            case 212:
                return new L2Ver21xInputStream(input, version == 211 ?
                        BLOWFISH_KEY_211 :
                        BLOWFISH_KEY_212);
            //RSA
            case 611:
            case 612:
            case 613:
            case 614:
                input = LameCrypt.wrapInput(input);
                version -= 200;
            case 411:
            case 412:
            case 413:
            case 414:
                BigInteger modulus = RSA_KEYS[version - 411][0];
                BigInteger exponent = RSA_KEYS[version - 411][1];
                return new L2Ver41xInputStream(input, modulus, exponent);
            default:
                throw new CryptoException("Unsupported crypt version: " + version);
        }
    }

    public static OutputStream getOutputStream(File file, int version) throws IOException, CryptoException {
        return encrypt(new FileOutputStream(file), file.getName(), version);
    }

    public static OutputStream encrypt(OutputStream output, String fileName, int version) throws IOException, CryptoException {
        if (version == NO_CRYPT) {
            return output;
        }

        writeHeader(output, version);
        switch (version) {
            //XOR
            case 811:
            case 821:
                output = LameCrypt.wrapOutput(output);
                version -= 700;
            case 111:
            case 121:
                return new L2Ver1x1OutputStream(output, version == 111 ?
                        XOR_KEY_111 :
                        getXORKey121(fileName));
            case 820:
                output = LameCrypt.wrapOutput(output);
            case 120:
                return new L2Ver120OutputStream(output);
            //BLOWFISH
            case 911:
            case 912:
                output = LameCrypt.wrapOutput(output);
                version -= 700;
            case 211:
            case 212:
                return new L2Ver21xOutputStream(output, version == 211 ?
                        BLOWFISH_KEY_211 :
                        BLOWFISH_KEY_212);
            //RSA
            case 611:
            case 612:
            case 613:
            case 614:
                output = LameCrypt.wrapOutput(output);
            case 411:
            case 412:
            case 413:
            case 414:
                return new L2Ver41xOutputStream(output, publicModulus, publicExponent);
            default:
                throw new CryptoException("Unsupported version: " + version);
        }
    }
}
