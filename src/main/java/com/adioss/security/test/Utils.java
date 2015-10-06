package com.adioss.security.test;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Formatter;

public class Utils {
    static void readFully(InputStream in, byte[] buf)
            throws IOException {
        readFully(in, buf, 0, buf.length);
    }

    static void readFully(InputStream in, byte[] buf, int off, int len)
            throws IOException {
        while (len > 0) {
            int rlen = in.read(buf, off, len);
            if (rlen < 0) {
                throw new EOFException();
            }
            off += rlen;
            len -= rlen;
        }
    }

    static void enc16be(int val, byte[] buf, int off) {
        buf[off] = (byte) (val >>> 8);
        buf[off + 1] = (byte) val;
    }

    static void enc24be(int val, byte[] buf, int off) {
        buf[off] = (byte) (val >>> 16);
        buf[off + 1] = (byte) (val >>> 8);
        buf[off + 2] = (byte) val;
    }

    static void enc32be(int val, byte[] buf, int off) {
        buf[off] = (byte) (val >>> 24);
        buf[off + 1] = (byte) (val >>> 16);
        buf[off + 2] = (byte) (val >>> 8);
        buf[off + 3] = (byte) val;
    }

    static int dec16be(byte[] buf, int off) {
        return ((buf[off] & 0xFF) << 8)
                | (buf[off + 1] & 0xFF);
    }

    static int dec24be(byte[] buf, int off) {
        return ((buf[off] & 0xFF) << 16)
                | ((buf[off + 1] & 0xFF) << 8)
                | (buf[off + 2] & 0xFF);
    }

    static int dec32be(byte[] buf, int off) {
        return ((buf[off] & 0xFF) << 24)
                | ((buf[off + 1] & 0xFF) << 16)
                | ((buf[off + 2] & 0xFF) << 8)
                | (buf[off + 3] & 0xFF);
    }

    /**
     * Compute the SHA-1 hash of some bytes, returning the hash
     * value in hexadecimal.
     */
    static String doSHA1(byte[] buf) {
        return doSHA1(buf, 0, buf.length);
    }

    static String doSHA1(byte[] buf, int off, int len) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA1");
            md.update(buf, off, len);
            byte[] hv = md.digest();
            Formatter f = new Formatter();
            for (byte b : hv) {
                f.format("%02x", b & 0xFF);
            }
            return f.toString();
        } catch (NoSuchAlgorithmException nsae) {
            throw new Error(nsae);
        }
    }
}
