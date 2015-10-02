package com.adioss.security;


import com.adioss.security.model.CipherDescription;
import com.adioss.security.model.Mode;

import java.util.List;
import java.util.Locale;

public class Main {
    public static void main(String[] args) throws Exception {
        String test = "local";
        Mode mode = Mode.valueOf(test.toUpperCase(Locale.ENGLISH));
        CipherManager cipherManager = new CipherManager(mode);
        List<CipherDescription> cipherDescriptions = cipherManager.listCipherDescriptions();
        cipherManager.validateAssumptions(cipherDescriptions);
        cipherManager.printCiphers(cipherDescriptions);
    }
}