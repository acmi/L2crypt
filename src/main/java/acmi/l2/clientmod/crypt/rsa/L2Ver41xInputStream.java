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
package acmi.l2.clientmod.crypt.rsa;

import acmi.l2.clientmod.crypt.CryptoException;

import javax.crypto.Cipher;
import java.io.DataInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Objects;
import java.util.zip.InflaterInputStream;

public final class L2Ver41xInputStream extends FilterInputStream implements L2Ver41x {
    private final int size;

    public L2Ver41xInputStream(InputStream input, BigInteger modulus, BigInteger exponent) throws IOException, CryptoException {
        super(null);
        RSAInputStream rsaInputStream = new RSAInputStream(Objects.requireNonNull(input, "stream"),
                Objects.requireNonNull(modulus, "modulus"),
                Objects.requireNonNull(exponent, "exponent"));
        size = Integer.reverseBytes(new DataInputStream(rsaInputStream).readInt());
        in = new InflaterInputStream(rsaInputStream);
    }

    public int getSize() {
        return size;
    }

    public static class RSAInputStream extends InputStream {
        private final DataInputStream input;

        private final Cipher cipher;

        private final byte[] buffer = new byte[128];
        private int startPosition;
        private int position;
        private int size;

        private boolean closed;

        public RSAInputStream(InputStream input, BigInteger modulus, BigInteger exponent) throws CryptoException {
            this.input = new DataInputStream(input);

            try {
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(modulus, exponent);
                cipher = Cipher.getInstance("RSA/ECB/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, keyFactory.generatePrivate(keySpec));
            } catch (GeneralSecurityException e) {
                throw new CryptoException(e);
            }
        }

        private void ensureOpen() throws IOException {
            if (closed) {
                throw new IOException("Stream closed");
            }
        }

        private boolean ensureFilled() throws IOException {
            if (position == size) {
                int remaining = buffer.length;
                while (remaining > 0) {
                    int count = input.read(buffer, buffer.length - remaining, remaining);
                    if (count < 0) {
                        return false;
                    }
                    remaining -= count;
                }

                try {
                    cipher.doFinal(buffer, 0, 128, buffer);
                } catch (GeneralSecurityException e) {
                    throw new CryptoException(e);
                }

                size = buffer[3] & 0xff;
                if (size > 124) {
                    throw new IllegalStateException("block data size too large");
                }

                startPosition = 128 - size - ((124 - size) % 4);
                position = 0;
            }
            return true;
        }

        @Override
        public int read() throws IOException {
            ensureOpen();
            if (!ensureFilled()) {
                return -1;
            }

            return buffer[startPosition + position++] & 0xFF;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (b == null) {
                throw new NullPointerException();
            } else if (off < 0 || len < 0 || len > b.length - off) {
                throw new IndexOutOfBoundsException();
            }

            ensureOpen();
            if (!ensureFilled()) {
                return -1;
            }

            int read = Math.min(len, available());
            System.arraycopy(buffer, startPosition + position, b, off, read);
            position += read;
            return read;
        }

        @Override
        public int available() throws IOException {
            ensureOpen();

            return size - position;
        }

        @Override
        public void close() throws IOException {
            if (!closed) {
                closed = true;
                input.close();
            }
        }
    }
}