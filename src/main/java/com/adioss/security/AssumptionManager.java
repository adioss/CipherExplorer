package com.adioss.security;

import com.adioss.security.model.CipherDescription;

public class AssumptionManager {
    public void validateAssumption(CipherDescription cipherDescription) {
        String name = cipherDescription.getName().toUpperCase();
        // Exclude SSL
        if (name.startsWith("SSL_")) {
            cipherDescription.getExclusions().add("SSL");
        }
        // Exclude EXPORT
        if (name.contains("EXPORT")) {
            cipherDescription.getExclusions().add("EXPORT");
        }
        // Exclude NULL
        if (name.contains("NULL")) {
            cipherDescription.getExclusions().add("NULL bulk cipher");
        }
        // Exclude anon auth
        if (name.startsWith("_ANON_")) {
            cipherDescription.getExclusions().add("ANON provide authentication");
        }
        // Cipher
        if (name.contains("_RC4_")) {
            cipherDescription.getExclusions().add("RC4 bulk cipher");
        }
        if (name.contains("_DES_")) {
            cipherDescription.getExclusions().add("DES bulk cipher");
        }
        if (name.contains("_3DES_")) {
            cipherDescription.getExclusions().add("3DES bulk cipher");
        }
        // Exclude md5 and sha1 message auth algo
        if (name.endsWith("_SHA")) {
            cipherDescription.getExclusions().add("SHA message auth algorithm");
        }
        if (name.endsWith("_MD5")) {
            cipherDescription.getExclusions().add("MD5 message auth algorithm");
        }
        // not usable cipher
        if (name.contains("TLS_EMPTY_RENEGOTIATION_INFO_SCSV")) {
            cipherDescription.getExclusions().add("TLS_EMPTY_RENEGOTIATION_INFO_SCSV");
        }
    }
}
