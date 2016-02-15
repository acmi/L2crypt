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
package acmi.l2.clientmod.crypt.xor;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

import static acmi.l2.clientmod.crypt.xor.L2Ver120.START_IND;
import static acmi.l2.clientmod.crypt.xor.L2Ver120.getXORKey;

public final class L2Ver120InputStream extends FilterInputStream {
    private int ind = START_IND;
    private int markInd;

    public L2Ver120InputStream(InputStream input) {
        super(Objects.requireNonNull(input, "stream"));
    }

    @Override
    public int read() throws IOException {
        int b = in.read();
        return b < 0 ? b : b ^ getXORKey(ind++);
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        int r = in.read(b, off, len);
        for (int i = 0; i < r; i++)
            b[off + i] ^= getXORKey(ind++);
        return r;
    }

    @Override
    public synchronized void mark(int readlimit) {
        super.mark(readlimit);

        markInd = ind;
    }

    @Override
    public synchronized void reset() throws IOException {
        super.reset();

        ind = markInd;
    }
}
