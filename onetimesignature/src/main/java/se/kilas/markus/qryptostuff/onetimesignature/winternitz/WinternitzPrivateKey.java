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
    
    public byte[][] signHash(final byte[] d) {
        if (v == null) {
            throw new IllegalStateException("Key not available for signing");
        }
        final int t = v.length;
        final int s = getMessageDigest().getDigestLength() * 8;
        
        final int t1 = s / paramW;
        System.out.println("t1 = s / w = " + s + " / " + paramW + " = " + t1);
        
        final int t2 = (log2(s / paramW) + 1 + paramW) / paramW;
        System.out.println("t2 = (log2(s/w) + 1 + w)/w = " + t2);
        
        System.out.println("d = " + Hex.toHexString(d));
        final byte[][] blocks = new byte[t1][];
        
        System.out.println("d.len=" + d.length + ", paddedD.len=" + t1 * paramW / 8);
        final byte[] paddedD = new byte[t1 * paramW / 8];
        System.arraycopy(d, 0, paddedD, paddedD.length - d.length, d.length);
        System.out.println("Dp= " + Hex.toHexString(paddedD));
        
        final BigInteger[] bInteger = new BigInteger[t1];
        for (int i = 0; i < blocks.length; i++) {
            blocks[i] = new byte[paramW / 8];
            System.arraycopy(paddedD, i * paramW / 8, blocks[i], 0, paramW / 8);
            bInteger[i] = BigIntegers.fromUnsignedByteArray(blocks[i]);
            System.out.println("b" + i + " = " + Hex.toHexString(blocks[i]) + " = " + bInteger[i]);
        }
        
        BigInteger c = new BigInteger("0");
        for (int i = 1; i < s / paramW; i++) {
            BigInteger twopowwbi = new BigInteger("2").pow(paramW).subtract(bInteger[i]);
            System.out.println("2^w - bi = 2^" + paramW + " - " + bInteger[i] + " = " + twopowwbi);
            c = c.add(twopowwbi);
        }
        
        
        
        byte[] C = BigIntegers.asUnsignedByteArray(c);
        int clt = t1 * 1 << paramW;//log2(t1) + paramW + 1;
        System.out.println("clt = " + clt);
        byte[] paddedC = new byte[BigIntegers.asUnsignedByteArray(new BigInteger(String.valueOf(clt))).length];
        System.out.println("C.len=" + C.length + ", paddedC.len=" + paddedC.length);
        System.out.println("C = " + c);
        System.out.println("c < log2(t1) + w + 1 <=>  c < " + clt);
        System.out.println("C = 0x" + Hex.toHexString(C));
        System.out.println("Cp= 0x" + Hex.toHexString(paddedC));
        System.arraycopy(C, 0, paddedC, paddedC.length - C.length, C.length);
        System.out.println("Cp= 0x" + Hex.toHexString(paddedC));
        
        final byte[][] cblocks = new byte[t2][];
        final BigInteger[] cbInteger = new BigInteger[t2];
        for (int i = 0; i < cblocks.length; i++) {
            cblocks[i] = new byte[paramW / 8];
            System.arraycopy(paddedC, i * paramW, cblocks[i], 0, paramW / 8);
            cbInteger[i] = BigIntegers.fromUnsignedByteArray(cblocks[i]);
            System.out.println("cb" + i + " = " + Hex.toHexString(cblocks[i]) + " = " + cbInteger[i]);
        }
        
        final byte[][] sig = new byte[t2][];
        
        for (int i = 0; i < t2; i++) {
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
