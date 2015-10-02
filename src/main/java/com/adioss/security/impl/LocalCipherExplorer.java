package com.adioss.security.impl;

import com.adioss.security.CipherExplorer;
import com.adioss.security.model.CipherDescription;

import javax.net.ssl.SSLServerSocketFactory;
import java.util.ArrayList;
import java.util.List;

public class LocalCipherExplorer implements CipherExplorer {

    public LocalCipherExplorer() {
    }

    @Override
    public List<CipherDescription> listCipherDescriptions() {
        List<CipherDescription> cipherDescriptions = new ArrayList<>();
        SSLServerSocketFactory ssf = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        String[] defaultCiphers = ssf.getDefaultCipherSuites();
        String[] availableCiphers = ssf.getSupportedCipherSuites();

        for (String defaultCipher : defaultCiphers) {
            cipherDescriptions.add(new CipherDescription(defaultCipher, true));
        }

        for (String availableCipher : availableCiphers) {
            CipherDescription cipherDescription = new CipherDescription(availableCipher, false);
            if (!cipherDescriptions.contains(cipherDescription)) {
                cipherDescriptions.add(cipherDescription);
            }
        }
        return cipherDescriptions;
    }
}
