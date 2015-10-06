package com.adioss.security.model;

import com.adioss.security.CipherExplorer;
import com.adioss.security.impl.DistantCipherExplorer;
import com.adioss.security.impl.Jre7CipherExplorer;
import com.adioss.security.impl.LocalCipherExplorer;

public enum Mode {
    LOCAL, DISTANT, JRE7, JRE8, BOTH;

    public CipherExplorer getCipherExplorer() {
        switch (this) {
            case LOCAL: {
                return new LocalCipherExplorer();
            }
            case DISTANT: {
                return new DistantCipherExplorer();
            }
            case BOTH: {
                return new DistantCipherExplorer();
            }
            case JRE7: {
                return new Jre7CipherExplorer();
            }
            case JRE8:
            default: {
                return new LocalCipherExplorer();
            }
        }
    }
}
