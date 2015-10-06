package com.adioss.security.test;

import java.security.SecureRandom;

public class Constants {
    static final SecureRandom RNG = new SecureRandom();
    static final int CLEAR = 0; // no encryption
    static final int WEAK = 1; // weak encryption: 40-bit key
    static final int MEDIUM = 2; // medium encryption: 56-bit key
    static final int STRONG = 3; // strong encryption

    static final int ALERT = 21;
    static final int HANDSHAKE = 22;
    static final int MAX_RECORD_LEN = 16384;

    /**
     * A constant SSLv2 CLIENT-HELLO message. Only one connection
     * is needed for SSLv2, since the server response will contain
     * _all_ the cipher suites that the server is willing to
     * support.
     * <p>
     * Note: when (mis)interpreted as a SSLv3+ record, this message
     * apparently encodes some data of (invalid) 0x80 type, using
     * protocol version TLS 44.1, and record length of 2 bytes.
     * Thus, the receiving part will quickly conclude that it will
     * not support that, instead of stalling for more data from the
     * client.
     */
    public static final byte[] SSL2_CLIENT_HELLO = {
            (byte) 0x80, (byte) 0x2E,  // header (record length)
            (byte) 0x01,              // message type (CLIENT HELLO)
            (byte) 0x00, (byte) 0x02,  // version (0x0002)
            (byte) 0x00, (byte) 0x15,  // cipher specs list length
            (byte) 0x00, (byte) 0x00,  // session ID length
            (byte) 0x00, (byte) 0x10,  // challenge length
            0x01, 0x00, (byte) 0x80,  // SSL_CK_RC4_128_WITH_MD5
            0x02, 0x00, (byte) 0x80,  // SSL_CK_RC4_128_EXPORT40_WITH_MD5
            0x03, 0x00, (byte) 0x80,  // SSL_CK_RC2_128_CBC_WITH_MD5
            0x04, 0x00, (byte) 0x80,  // SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5
            0x05, 0x00, (byte) 0x80,  // SSL_CK_IDEA_128_CBC_WITH_MD5
            0x06, 0x00, (byte) 0x40,  // SSL_CK_DES_64_CBC_WITH_MD5
            0x07, 0x00, (byte) 0xC0,  // SSL_CK_DES_192_EDE3_CBC_WITH_MD5
            0x54, 0x54, 0x54, 0x54,  // challenge data (16 bytes)
            0x54, 0x54, 0x54, 0x54,
            0x54, 0x54, 0x54, 0x54,
            0x54, 0x54, 0x54, 0x54
    };

}
