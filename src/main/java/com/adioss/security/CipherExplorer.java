package com.adioss.security;

import com.adioss.security.model.CipherDescription;

import java.util.List;

public interface CipherExplorer {
    List<CipherDescription> listCipherDescriptions();
}
