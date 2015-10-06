package com.adioss.security.test;/*
 * Command-line tool to test a SSL/TLS server for some vulnerabilities.
 * =====================================================================
 *
 * This application connects to the provided SSL/TLS server (by name and
 * port) and extracts the following information:
 * - supported versions (SSL 2.0, SSL 3.0, TLS 1.0 to 1.2)
 * - support of Deflate compression
 * - list of supported cipher suites (for each protocol version)
 * - BEAST/CRIME vulnerabilities.
 *
 * BEAST and CRIME are client-side attack, but the server can protect the
 * client by refusing to use the feature combinations which can be
 * attacked. For CRIME, the weakness is Deflate compression. For BEAST,
 * the attack conditions are more complex: it works with CBC ciphers with
 * SSL 3.0 and TLS 1.0. Hence, a server fails to protect the client against
 * BEAST if it does not enforce usage of RC4 over CBC ciphers under these
 * protocol versions, if given the choice.
 *
 * (The BEAST test considers only the cipher suites with strong
 * encryption; if the server supports none, then there are bigger
 * problems. We also assume that all clients support RC4-128; thus, the
 * server protects the client if it selects RC4-128 even if some strong
 * CBC-based ciphers are announced as supported by the client with a
 * higher preference level.)
 *
 * ----------------------------------------------------------------------
 * Copyright (c) 2012  Thomas Pornin <pornin@bolet.org>
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * ----------------------------------------------------------------------
 */

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.*;

import static com.adioss.security.test.CipherSuiteUnion.CIPHER_SUITES;
import static com.adioss.security.test.Constants.*;
import static com.adioss.security.test.Utils.*;

public class TestSSLServer {

    static void usage() {
        System.err.println("usage: TestSSLServer servername [ port ]");
        System.exit(1);
    }

    public static void main(String[] args) throws IOException {
        if (args.length == 0 || args.length > 2) {
            usage();
        }
        String name = args[0];
        int port = 443;
        if (args.length == 2) {
            try {
                port = Integer.parseInt(args[1]);
            } catch (NumberFormatException nfe) {
                usage();
            }
            if (port <= 0 || port > 65535) {
                usage();
            }
        }
        InetSocketAddress inetSocketAddress = new InetSocketAddress(name, port);

        Set<Integer> protocolVersions = new TreeSet<>();
        boolean compress = false;
        for (int v = 0x0300; v <= 0x0303; v++) {
            ServerHello serverHello = connect(inetSocketAddress, v, CIPHER_SUITES.keySet());
            if (serverHello == null) {
                continue;
            }
            protocolVersions.add(serverHello.protocolVersion);
            if (serverHello.compression == 1) {
                compress = true;
            }
        }

        ServerHelloSSLv2 serverHelloSSLv2 = connectV2(inetSocketAddress);

        if (serverHelloSSLv2 != null) {
            protocolVersions.add(0x0200);
        }

        if (protocolVersions.size() == 0) {
            System.out.println("No SSL/TLS server at " + inetSocketAddress);
            System.exit(1);
        }
        System.out.print("Supported versions:");
        for (int protocolVersion : protocolVersions) {
            System.out.print(" ");
            System.out.print(versionString(protocolVersion));
        }
        System.out.println();
        System.out.println("Deflate compression: " + (compress ? "YES" : "no"));

        System.out.println("Supported cipher suites" + " (ORDER IS NOT SIGNIFICANT):");
        Set<Integer> lastSuppCS = null;
        Map<Integer, Set<Integer>> supportedCipherSuites = new TreeMap<>();
        Set<String> certID = new TreeSet<>();

        if (serverHelloSSLv2 != null) {
            System.out.println("  " + versionString(0x0200));
            Set<Integer> vc2 = new TreeSet<>();
            for (int cipherSuite : serverHelloSSLv2.cipherSuites) {
                vc2.add(cipherSuite);
            }
            for (int c : vc2) {
                System.out.println("     " + cipherSuiteStringV2(c));
            }
            supportedCipherSuites.put(0x0200, vc2);
            if (serverHelloSSLv2.serverCertName != null) {
                certID.add(serverHelloSSLv2.serverCertHash + ": " + serverHelloSSLv2.serverCertName);
            }
        }

        for (int protocolVersion : protocolVersions) {
            if (protocolVersion == 0x0200) {
                continue;
            }
            Set<Integer> vsc = supportedSuites(inetSocketAddress, protocolVersion, certID);
            supportedCipherSuites.put(protocolVersion, vsc);
            if (lastSuppCS == null || !lastSuppCS.equals(vsc)) {
                System.out.println("  " + versionString(protocolVersion));
                for (int c : vsc) {
                    System.out.println("     " + cipherSuiteString(c));
                }
                lastSuppCS = vsc;
            } else {
                System.out.println("  (" + versionString(protocolVersion) + ": idem)");
            }
        }
        System.out.println("----------------------");
        if (certID.size() == 0) {
            System.out.println("No server certificate !");
        } else {
            System.out.println("Server certificate(s):");
            for (String cc : certID) {
                System.out.println("  " + cc);
            }
        }
        System.out.println("----------------------");
        int agMaxStrength = STRONG;
        int agMinStrength = STRONG;
        boolean vulnBEAST = false;
        for (int v : protocolVersions) {
            Set<Integer> vsc = supportedCipherSuites.get(v);
            agMaxStrength = Math.min(maxStrength(vsc), agMaxStrength);
            agMinStrength = Math.min(minStrength(vsc), agMinStrength);
            if (!vulnBEAST) {
                vulnBEAST = testBEAST(inetSocketAddress, v, vsc);
            }
        }
        System.out.println("Minimal encryption strength:     " + strengthString(agMinStrength));
        System.out.println("Achievable encryption strength:  " + strengthString(agMaxStrength));
        System.out.println("BEAST status: " + (vulnBEAST ? "vulnerable" : "protected"));
        System.out.println("CRIME status: " + (compress ? "vulnerable" : "protected"));
    }

    /**
     * Get cipher suites supported by the server. This is done by
     * repeatedly contacting the server, each time removing from our
     * list of supported suites the suite which the server just
     * selected. We keep on until the server can no longer respond
     * to us with a ServerHello.
     */
    static Set<Integer> supportedSuites(InetSocketAddress isa, int version,
                                        Set<String> serverCertID) {
        Set<Integer> cs = new TreeSet<>(CIPHER_SUITES.keySet());
        Set<Integer> rs = new TreeSet<>();
        for (; ; ) {
            ServerHello sh = connect(isa, version, cs);
            if (sh == null) {
                break;
            }
            if (!cs.contains(sh.cipherSuite)) {
                System.err.printf("[ERR: server wants to use"
                        + " cipher suite 0x%04X which client"
                        + " did not announce]", sh.cipherSuite);
                System.err.println();
                break;
            }
            cs.remove(sh.cipherSuite);
            rs.add(sh.cipherSuite);
            if (sh.serverCertName != null) {
                serverCertID.add(sh.serverCertHash
                        + ": " + sh.serverCertName);
            }
        }
        return rs;
    }

    static int minStrength(Set<Integer> supp) {
        int m = STRONG;
        for (int suite : supp) {
            CipherSuite cs = CIPHER_SUITES.get(suite);
            if (cs == null) {
                continue;
            }
            if (cs.strength < m) {
                m = cs.strength;
            }
        }
        return m;
    }

    static int maxStrength(Set<Integer> supp) {
        int m = CLEAR;
        for (int suite : supp) {
            CipherSuite cs = CIPHER_SUITES.get(suite);
            if (cs == null) {
                continue;
            }
            if (cs.strength > m) {
                m = cs.strength;
            }
        }
        return m;
    }

    static boolean testBEAST(InetSocketAddress isa,
                             int version, Set<Integer> supp) {
        /**
         * TLS 1.1+ is not vulnerable to BEAST.
         * We do not test SSLv2 either.
         */
        if (version < 0x0300 || version > 0x0301) {
            return false;
        }

        /**
         * BEAST attack works if the server allows the client to
         * use a CBC cipher. Existing clients also supports RC4,
         * so we consider that a server protects the clients if
         * it chooses RC4 over CBC streams when given the choice.
         * We only consider strong cipher suites here.
         */
        List<Integer> strongCBC = new ArrayList<>();
        List<Integer> strongStream = new ArrayList<>();
        for (int suite : supp) {
            CipherSuite cs = CIPHER_SUITES.get(suite);
            if (cs == null) {
                continue;
            }
            if (cs.strength < STRONG) {
                continue;
            }
            if (cs.isCBC) {
                strongCBC.add(suite);
            } else {
                strongStream.add(suite);
            }
        }
        if (strongCBC.size() == 0) {
            return false;
        }
        if (strongStream.size() == 0) {
            return true;
        }
        List<Integer> ns = new ArrayList<>(strongCBC);
        ns.addAll(strongStream);
        ServerHello serverHello = connect(isa, version, ns);
        return !strongStream.contains(serverHello.cipherSuite);
    }

    static String versionString(int version) {
        if (version == 0x0200) {
            return "SSLv2";
        } else if (version == 0x0300) {
            return "SSLv3";
        } else if ((version >>> 8) == 0x03) {
            return "TLSv1." + ((version & 0xFF) - 1);
        } else {
            return String.format("UNKNOWN_VERSION:0x%04X", version);
        }
    }

    /**
     * Connect to the server, send a ClientHello, and decode the
     * response (ServerHello). On error, null is returned.
     */
    static ServerHello connect(InetSocketAddress isa, int version, Collection<Integer> cipherSuites) {
        Socket socket = null;
        try {
            socket = new Socket();
            try {
                socket.connect(isa);
            } catch (IOException ioe) {
                System.err.println("could not connect to " + isa + ": " + ioe.toString());
                return null;
            }
            byte[] ch = makeClientHello(version, cipherSuites);
            OutputRecord orec = new OutputRecord(socket.getOutputStream());
            orec.setType(HANDSHAKE);
            orec.setVersion(version);
            orec.write(ch);
            orec.flush();
            return new ServerHello(socket.getInputStream());
        } catch (IOException ioe) {
            // ignored
        } finally {
            try {
                if (socket != null) {
                    socket.close();
                }
            } catch (IOException ioe) {
                // ignored
            }
        }
        return null;
    }

    /**
     * Connect to the server, send a SSLv2 CLIENT HELLO, and decode
     * the response (SERVER HELLO). On error, null is returned.
     */
    static ServerHelloSSLv2 connectV2(InetSocketAddress isa) {
        Socket socket = null;
        try {
            socket = new Socket();
            try {
                socket.connect(isa);
            } catch (IOException ioe) {
                System.err.println("could not connect to " + isa + ": " + ioe.toString());
                return null;
            }
            socket.getOutputStream().write(SSL2_CLIENT_HELLO);
            return new ServerHelloSSLv2(socket.getInputStream());
        } catch (IOException ioe) {
            // ignored
        } finally {
            try {
                if (socket != null) {
                    socket.close();
                }
            } catch (IOException ioe) {
                // ignored
            }
        }
        return null;
    }

    /*
     * Build a ClientHello message, with the specified maximum
     * supported version, and list of cipher suites.
     */
    static byte[] makeClientHello(int version, Collection<Integer> cipherSuites) {
        try {
            return makeClientHello0(version, cipherSuites);
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    static byte[] makeClientHello0(int version, Collection<Integer> cipherSuites)
            throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();

		/*
         * Message header:
		 *   message type: one byte (1 = "ClientHello")
		 *   message length: three bytes (this will be adjusted
		 *   at the end of this method).
		 */
        b.write(1);
        b.write(0);
        b.write(0);
        b.write(0);

		/*
         * The maximum version that we intend to support.
		 */
        b.write(version >>> 8);
        b.write(version);

		/*
         * The client random has length 32 bytes, but begins with
		 * the client's notion of the current time, over 32 bits
		 * (seconds since 1970/01/01 00:00:00 UTC, not counting
		 * leap seconds).
		 */
        byte[] rand = new byte[32];
        RNG.nextBytes(rand);
        enc32be((int) (System.currentTimeMillis() / 1000), rand, 0);
        b.write(rand);

		/*
         * We send an empty session ID.
		 */
        b.write(0);

		/*
         * The list of cipher suites (list of 16-bit values; the
		 * list length in bytes is written first).
		 */
        int num = cipherSuites.size();
        byte[] cs = new byte[2 + num * 2];
        enc16be(num * 2, cs, 0);
        int j = 2;
        for (int s : cipherSuites) {
            enc16be(s, cs, j);
            j += 2;
        }
        b.write(cs);

		/*
         * Compression methods: we claim to support Deflate (1)
		 * and the standard no-compression (0), with Deflate
		 * being preferred.
		 */
        b.write(2);
        b.write(1);
        b.write(0);

		/*
         * If we had extensions to add, they would go here.
		 */

		/*
         * We now get the message as a blob. The message length
		 * must be adjusted in the header.
		 */
        byte[] msg = b.toByteArray();
        enc24be(msg.length - 4, msg, 1);
        return msg;
    }

    static String strengthString(int strength) {
        switch (strength) {
            case CLEAR:
                return "no encryption";
            case WEAK:
                return "weak encryption (40-bit)";
            case MEDIUM:
                return "medium encryption (56-bit)";
            case STRONG:
                return "strong encryption (96-bit or more)";
            default:
                throw new Error("strange strength: " + strength);
        }
    }

    static String cipherSuiteString(int suite) {
        CipherSuite cs = CIPHER_SUITES.get(suite);
        if (cs == null) {
            return String.format("UNKNOWN_SUITE:0x%04X", cs);
        } else {
            return cs.name;
        }
    }

    static String cipherSuiteStringV2(int suite) {
        CipherSuite cs = CIPHER_SUITES.get(suite);
        if (cs == null) {
            return String.format("UNKNOWN_SUITE:%02X,%02X,%02X",
                    suite >> 16, (suite >> 8) & 0xFF, suite & 0XFF);
        } else {
            return cs.name;
        }
    }
}
