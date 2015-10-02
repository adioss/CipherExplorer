package com.adioss.security;

import com.adioss.security.model.CipherDescription;
import com.adioss.security.model.Mode;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

public class CipherManager {
    private final CipherExplorer cipherExplorer;
    private final AssumptionManager assumptionManager;

    public CipherManager(Mode mode) {
        cipherExplorer = mode.getCipherExplorer();
        assumptionManager = new AssumptionManager();
    }

    List<CipherDescription> listCipherDescriptions() {
        return cipherExplorer.listCipherDescriptions();
    }

    void validateAssumptions(List<CipherDescription> cipherDescriptions) {
        cipherDescriptions.forEach(assumptionManager::validateAssumption);
    }

    void printCiphers(List<CipherDescription> cipherDescriptions) {
//        Set<CipherDescription> excluded = new TreeSet<>((o1, o2) -> {
//
//            return 0;
//        });
        Set<CipherDescription> included = new HashSet<>();
        Set<CipherDescription> excluded = new HashSet<>();
        System.out.println("Nb of cipherDescriptions supported: " + cipherDescriptions.size());
        for (CipherDescription cipherDescription : cipherDescriptions) {
            System.out.println(cipherDescription.toString());
            if (cipherDescription.getExclusions().size() > 0 || !cipherDescription.isEnableByDefault()) {
                excluded.add(cipherDescription);
            } else {
                included.add(cipherDescription);
            }
        }

        System.out.printf("To include(%d): %n", included.size());
        included.stream().sorted((o1, o2) -> o1.getName().compareTo(o2.getName())).forEach(printName());
        System.out.printf("To exclude(%d): %n", excluded.size());
        excluded.stream().sorted((o1, o2) -> o1.getName().compareTo(o2.getName())).forEach(printName());
    }

    private Consumer<CipherDescription> print() {
        return System.out::println;
    }

    private Consumer<CipherDescription> printName() {
        return cipherDescription -> System.out.println(cipherDescription.getName());
    }
}
