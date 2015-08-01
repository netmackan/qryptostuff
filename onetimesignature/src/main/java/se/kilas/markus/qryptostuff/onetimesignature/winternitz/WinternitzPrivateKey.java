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
package se.kilas.markus.qryptostuff.onetimesignature.winternitz;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Random;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import se.kilas.markus.qryptostuff.onetimesignature.OTSPrivateKey;

/**
 *
 * @author Markus Kilås
 */
public class WinternitzPrivateKey extends WinternitzKey implements OTSPrivateKey {

    public static WinternitzPrivateKey generate(final MessageDigest md, final Random random, final int paramW, final int t) {
        
        final int s = md.getDigestLength();
        final byte[][] x = new byte[t][];
        
        for (int i = 0; i < x.length; i++) {
            x[i] = new byte[s];
            random.nextBytes(x[i]);
        }
        return new WinternitzPrivateKey(x, md, paramW);
    }

    public WinternitzPrivateKey(final byte[][] v, final MessageDigest md, final int paramW) {
        super(v, md, paramW);
    }

    public WinternitzPublicKey derivePublic() {
        if (v == null) {
            throw new IllegalStateException("Key not available");
        }
        final byte[][] y = new byte[v.length][];
        for (int i = 0; i < v.length; i++) {
            y[i] = hash(v[i]);
            //System.out.println("y["+ i + "] = " + Hex.toHexString(y[i]));
            //System.out.println("2^w = 2^" + paramW + " = " + (1 << paramW));
            for (int j = 1; j < 1 << paramW - 1; j++) {
                y[i] = hash(y[i]);
                //System.out.println("y["+ i + "] = " + Hex.toHexString(y[i]));
            }
        }
        return new WinternitzPublicKey(y, getMessageDigest(), paramW);
    }

    @Override
    public byte[][] sign(final byte[] message) {
        if (v == null) {
            throw new IllegalStateException("Key not available for signing");
        }
        return signHash(hash(message)); // assuming as message should be divided in s/w blocks of length w
    }
    
    public byte[][] signHash(final byte[] M) {
        if (v == null) {
            throw new IllegalStateException("Key not available for signing");
        }
        final int t = v.length;
        final int s = getMessageDigest().getDigestLength();
        
        final int numBlocks = s / paramW;
        System.out.println("blocks = s / w = " + s + " / " + paramW + " = " + numBlocks);
        System.out.println("M = " + Hex.toHexString(M));
        final byte[][] blocks = new byte[numBlocks][paramW];
        final BigInteger[] bInteger = new BigInteger[numBlocks];
        for (int i = 0; i < blocks.length; i++) {
            blocks[i] = new byte[paramW];
            System.arraycopy(M, i * paramW, blocks[i], 0, paramW);
            bInteger[i] = BigIntegers.fromUnsignedByteArray(blocks[i]);
            System.out.println("b" + i + " = " + Hex.toHexString(blocks[i]) + " = " + bInteger[i]);
        }
        
        BigInteger c = new BigInteger("0");
        for (int i = 1; i < s / paramW; i++) {
            c.add(new BigInteger("2").pow(1 << paramW).subtract(bInteger[i]));
        }
        System.out.println("C = " + c);
        
        final int numCBlocks = (log2(s / paramW) + 1 + paramW) / paramW;
        System.out.println("cblocks = (log2(s/w) + 1 + w)/w = " + numCBlocks);
        final byte[][] cblocks = new byte[numCBlocks][paramW];
        final BigInteger[] cbInteger = new BigInteger[numCBlocks];
        for (int i = 0; i < cblocks.length; i++) {
            cblocks[i] = new byte[paramW];
            System.arraycopy(M, i * paramW, cblocks[i], 0, paramW);
            cbInteger[i] = BigIntegers.fromUnsignedByteArray(cblocks[i]);
            System.out.println("cb" + i + " = " + Hex.toHexString(cblocks[i]) + " = " + cbInteger[i]);
        }
        
        final byte[][] sig = new byte[numCBlocks][];
        
        for (int i = 0; i < numCBlocks; i++) {
            sig[i] = hash(v[i]);
            for (int j = 1; j < cbInteger[i].intValue(); j++) {
                sig[i] = hash(v[i]);
            }
        }
        
        clear();
        
        return sig;
    }

    private void clear() {
        for (int i = 0; i < v.length; i++) {
            v[i] = null;
        }
        v = null;
    }

    @Override
    public String toString() {
        return "PrivateKey" + "(" + getDigestAlgorithm() + ")";
    }

}
