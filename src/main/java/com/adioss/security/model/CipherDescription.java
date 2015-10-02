package com.adioss.security.model;

import java.util.ArrayList;
import java.util.List;

public class CipherDescription {
    private final String name;
    private final List<String> exclusions;
    private final boolean isEnableByDefault;

    public CipherDescription(String name, boolean isEnableByDefault) {
        this.name = name;
        this.exclusions = new ArrayList<>();
        this.isEnableByDefault = isEnableByDefault;
    }

    public String getName() {
        return name;
    }

    public List<String> getExclusions() {
        return exclusions;
    }

    public boolean isEnableByDefault() {
        return isEnableByDefault;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        CipherDescription cipherDescription = (CipherDescription) o;

        return !(name != null ? !name.equals(cipherDescription.name) : cipherDescription.name != null);

    }

    @Override
    public int hashCode() {
        return name != null ? name.hashCode() : 0;
    }

    @Override
    public String toString() {
        return "CipherDescription{" +
                "name='" + name + '\'' +
                ", exclusions=" + exclusions +
                ", isEnableByDefault=" + isEnableByDefault +
                '}';
    }
}
