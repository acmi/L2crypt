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
package acmi.l2.clientmod.crypt.lame;

import acmi.l2.clientmod.crypt.L2Crypt;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class LameCrypt {
    public static String cryptString = "Range check error while converting variant of type (%s) into type (%s)";

    public static InputStream wrapInput(InputStream input) {
        return new InputStream() {
            private int pos = L2Crypt.HEADER_SIZE % cryptString.length();

            @Override
            public int read() throws IOException {
                int b = input.read();

                if (b == -1)
                    return -1;

                b ^= cryptString.charAt(pos++);

                if (pos == cryptString.length())
                    pos = 0;

                return b;
            }
        };
    }

    public static OutputStream wrapOutput(OutputStream output) {
        return new OutputStream() {
            private int pos = L2Crypt.HEADER_SIZE % cryptString.length();

            @Override
            public void write(int b) throws IOException {
                b ^= cryptString.charAt(pos++);

                if (pos == cryptString.length())
                    pos = 0;

                output.write(b);
            }
        };
    }
}
