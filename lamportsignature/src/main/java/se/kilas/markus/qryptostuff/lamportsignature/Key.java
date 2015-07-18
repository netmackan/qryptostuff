/*
 * Copyright (C) 2015 Markus Kilås
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package se.kilas.markus.qryptostuff.lamportsignature;

import java.security.MessageDigest;

/**
 *
 * @author Markus Kilås
 */
public abstract class Key {

    private final MessageDigest md;
    protected byte[][][] v;

    protected Key(byte[][][] v, MessageDigest md) {
        if (md.getDigestLength() * 8 != v.length) {
            throw new IllegalArgumentException("Key should have the same number of pairs as the bit length of the message digest: " + md.getDigestLength() * 8 + " but was " + v.length);
        }
        this.md = md;
        this.v = v;
    }

    public String getDigestAlgorithm() {
        return md.getAlgorithm();
    }
    
    public int getSize() {
        return md.getDigestLength();
    }
    
    protected MessageDigest getMessageDigest() {
        return md;
    }

    protected byte[][] selectBasedOnHash(byte[] hash) {
        if (hash.length * 8 != v.length) {
            throw new IllegalArgumentException("Hash should have the same bit length as key: " + v.length + " but was " + hash.length * 8);
        }

        byte[][] result = new byte[hash.length * 8][];
        
        for (int i = 0; i < hash.length; i++) {
            for (int j = 0; j < 8; j++) {
                if ((hash[i] & 0x80 >> j) != 0) {
                    result[i * 8 + j] = v[i * 8 + j][1]; 
                } else {
                    result[i * 8 + j] = v[i * 8 + j][0];
                }
            }
        }
        return result;
    }

    protected byte[] hash(byte[] value) {
        md.reset();
        return md.digest(value);
    }
    
}
