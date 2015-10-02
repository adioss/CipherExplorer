package com.adioss.security.model;

import com.adioss.security.CipherExplorer;
import com.adioss.security.impl.DistantCipherExplorer;
import com.adioss.security.impl.LocalCipherExplorer;

public enum Mode {
    LOCAL("local"), DISTANT("distant"), INFO("info");

    private final String type;

    Mode(String type) {
        this.type = type;
    }

    public CipherExplorer getCipherExplorer() {
        switch (this) {
            case LOCAL: {
                return new LocalCipherExplorer();
            }
            case DISTANT: {
                return new DistantCipherExplorer();
            }
            case INFO:
            default: {
                return new LocalCipherExplorer();
            }
        }
    }

    public String getType() {
        return type;
    }
}
