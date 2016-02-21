/*
 * Copyright (c) 2016 acmi
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
package acmi.l2.clientmod.crypt.rsa;

import acmi.l2.clientmod.crypt.CryptoException;
import acmi.l2.clientmod.crypt.FinishableOutputStream;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Objects;
import java.util.zip.DeflaterOutputStream;

public final class L2Ver41xOutputStream extends FinishableOutputStream implements L2Ver41x {
    private ByteArrayOutputStream dataBuffer = new ByteArrayOutputStream(0);

    private boolean finished;

    public L2Ver41xOutputStream(OutputStream output, BigInteger modulus, BigInteger exponent) {
        super(new RSAOutputStream(Objects.requireNonNull(output, "stream"), Objects.requireNonNull(modulus, "modulus"), Objects.requireNonNull(exponent, "exponent")));
    }

    @Override
    public void write(int b) throws IOException {
        if (finished)
            throw new IOException("write beyond end of stream");

        dataBuffer.write(b);
    }

    @Override
    public void finish() throws IOException {
        if (finished)
            return;

        finished = true;

        new DataOutputStream(out).writeInt(Integer.reverseBytes(dataBuffer.size()));

        DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(out);
        dataBuffer.writeTo(deflaterOutputStream);
        deflaterOutputStream.finish();

        ((RSAOutputStream) out).finish();
    }

    private static class RSAOutputStream extends FinishableOutputStream {
        private Cipher cipher;

        private ByteBuffer dataBuffer = ByteBuffer.allocate(124);
        private byte[] block = new byte[128];

        private boolean finished;

        public RSAOutputStream(OutputStream output, BigInteger modulus, BigInteger exponent) {
            super(output);

            try {
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
                cipher = Cipher.getInstance("RSA/ECB/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, keyFactory.generatePublic(keySpec));
            } catch (GeneralSecurityException e) {
                throw new CryptoException(e);
            }
        }

        @Override
        public void write(int b) throws IOException {
            if (finished)
                throw new IOException("write beyond end of stream");

            dataBuffer.put((byte) b);

            if (dataBuffer.position() == dataBuffer.limit()) {
                writeData();

                dataBuffer.clear();
            }
        }

        @Override
        public void finish() throws IOException {
            if (finished)
                return;

            finished = true;
            writeData();
            flush();
        }

        private void writeData() throws IOException {
            int size = dataBuffer.position();
            if (size == 0)
                return;

            Arrays.fill(block, (byte) 0);
            block[3] = (byte) (size & 0xff);
            System.arraycopy(dataBuffer.array(), 0, block, 128 - size - ((124 - size) % 4), size);

            try {
                cipher.doFinal(block, 0, 128, block);
            } catch (GeneralSecurityException e) {
                throw new CryptoException(e);
            }

            out.write(block);
        }
    }
}
