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

import acmi.l2.clientmod.crypt.FinishableOutputStream;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

public final class L2Ver21xOutputStream extends FinishableOutputStream implements L2Ver21x {
    private BlowfishEngine blowfish = new BlowfishEngine();

    private byte[] writeBuffer = new byte[8];
    private ByteBuffer dataBuffer = ByteBuffer.allocate(8);

    private boolean finished;

    public L2Ver21xOutputStream(OutputStream output, byte[] key) {
        super(Objects.requireNonNull(output, "stream"));
        blowfish.init(true, Objects.requireNonNull(key, "key"));
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
        if (dataBuffer.position() == 0)
            return;

        Arrays.fill(dataBuffer.array(), dataBuffer.position(), dataBuffer.limit(), (byte) 0);
        blowfish.processBlock(dataBuffer.array(), dataBuffer.arrayOffset(), writeBuffer, 0);
        out.write(writeBuffer);
    }
}