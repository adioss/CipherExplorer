package com.adioss.security.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static com.adioss.security.test.Utils.*;

/*
 * This class represents the response of a server which knows
 $ SSLv2. It includes the list of cipher suites, and the
 * identification of the server certificate.
 */
public class ServerHelloSSLv2 {


    int[] cipherSuites;
    String serverCertName;
    String serverCertHash;

    ServerHelloSSLv2(InputStream in) throws IOException {
        // Record length
        byte[] buf = new byte[2];
        readFully(in, buf);
        int len = dec16be(buf, 0);
        if ((len & 0x8000) == 0) {
            throw new IOException("not a SSLv2 record");
        }
        len &= 0x7FFF;
        if (len < 11) {
            throw new IOException("not a SSLv2 server hello");
        }
        buf = new byte[11];
        readFully(in, buf);
        if (buf[0] != 0x04) {
            throw new IOException("not a SSLv2 server hello");
        }
        int certLen = dec16be(buf, 5);
        int csLen = dec16be(buf, 7);
        int connIdLen = dec16be(buf, 9);
        if (len != 11 + certLen + csLen + connIdLen) {
            throw new IOException("not a SSLv2 server hello");
        }
        if (csLen == 0 || csLen % 3 != 0) {
            throw new IOException("not a SSLv2 server hello");
        }
        byte[] cert = new byte[certLen];
        readFully(in, cert);
        byte[] cs = new byte[csLen];
        readFully(in, cs);
        byte[] connId = new byte[connIdLen];
        readFully(in, connId);
        cipherSuites = new int[csLen / 3];
        for (int i = 0, j = 0; i < csLen; i += 3, j++) {
            cipherSuites[j] = dec24be(cs, i);
        }
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate xc = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(cert));
            serverCertName = xc.getSubjectX500Principal().toString();
            serverCertHash = doSHA1(cert);
        } catch (CertificateException e) {
            // ignored
        }
    }
}
