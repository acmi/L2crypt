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
package acmi.l2.clientmod.crypt.blowfish;

import acmi.l2.clientmod.crypt.CryptoException;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Objects;

public final class L2Ver21xInputStream extends InputStream implements L2Ver21x {
    private DataInputStream in;
    private BlowfishEngine blowfish = new BlowfishEngine();

    private byte[] readBuffer = new byte[8];
    private ByteBuffer dataBuffer = ByteBuffer.allocate(8);

    {
        dataBuffer.position(dataBuffer.limit());
    }

    public L2Ver21xInputStream(InputStream input, byte[] key) {
        in = new DataInputStream(Objects.requireNonNull(input, "stream"));
        blowfish.init(false, Objects.requireNonNull(key, "key"));
    }

    @Override
    public int read() throws IOException {
        if (dataBuffer.position() == dataBuffer.limit()) {
            in.readFully(readBuffer);
            dataBuffer.clear();
            try {
                blowfish.processBlock(readBuffer, 0, dataBuffer.array(), dataBuffer.arrayOffset());
            } catch (GeneralSecurityException e) {
                throw new CryptoException(e);
            }
        }
        return dataBuffer.get() & 0xff;
    }

    @Override
    public int available() throws IOException {
        return dataBuffer.limit() - dataBuffer.position();
    }

    @Override
    public void close() throws IOException {
        in.close();
    }
}
