package com.adioss.security.impl;

import com.adioss.security.CipherExplorer;
import com.adioss.security.model.CipherConstant;
import com.adioss.security.model.CipherDescription;

import java.util.List;

public class Jre7CipherExplorer implements CipherExplorer {
    @Override
    public List<CipherDescription> listCipherDescriptions() {
        return CipherConstant.STANDARD_JRE7_CIPHER_LIST;
    }
}
