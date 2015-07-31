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
package se.kilas.markus.qryptostuff.onetimesignature.lamport;

import java.security.MessageDigest;
import java.util.Random;
import se.kilas.markus.qryptostuff.onetimesignature.OTSPrivateKey;

/**
 *
 * @author Markus Kilås
 */
public class LamportPrivateKey extends LamportKey implements OTSPrivateKey {
    
    public static LamportPrivateKey generate(final MessageDigest md, final Random random) {
        final int length = md.getDigestLength();
        final byte[][][] y = new byte[length * 8][2][];
        for (byte[][] y1 : y) {
            for (int j = 0; j < y1.length; j++) {
                y1[j] = new byte[length];
                random.nextBytes(y1[j]);
            }
        }
        return new LamportPrivateKey(y, md);
    }
    
    public LamportPrivateKey(final byte[][][] v, final MessageDigest md) {
        super(v, md);
    }

    public LamportPublicKey derivePublic() {
        if (v == null) {
            throw new IllegalStateException("Key not available");
        }
        final byte[][][] z  = new byte[v.length][2][];
        for (int i = 0; i < v.length; i++) {
            for (int j = 0; j < 2; j++) {
                z[i][j] = hash(v[i][j]);
            }
        }
        return new LamportPublicKey(z, getMessageDigest());
    }
    
    @Override
    public byte[][] sign(final byte[] message) {
        if (v == null) {
            throw new IllegalStateException("Key not available for signing");
        }
        return signHash(hash(message));
    }
    
    public byte[][] signHash(final byte[] hash) {
        if (v == null) {
            throw new IllegalStateException("Key not available for signing");
        }
        final byte[][] result = selectBasedOnHash(hash);
        clear();
        return result;
    }

    private void clear() {
        for (int i = 0; i < v.length; i++) {
            for (int j = 0; j < v[i].length; j++) {
                v[i][j] = null;
            }
            v[i] = null;
        }
        v = null;
    }
    
    @Override
    public String toString() {
        return "PrivateKey" + "(" + getDigestAlgorithm() + ")";
    }
    
}
