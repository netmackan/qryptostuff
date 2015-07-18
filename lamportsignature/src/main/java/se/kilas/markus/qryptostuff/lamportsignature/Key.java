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

import java.math.BigInteger;
import java.security.MessageDigest;

/**
 *
 * @author Markus Kilås
 */
public abstract class Key {

    private final boolean publicType;
    private final MessageDigest md;
    protected BigInteger[][] v;

    protected Key(boolean publicType, MessageDigest md, BigInteger[][] v) {
        if (md.getDigestLength() * 8 != v.length) {
            throw new IllegalArgumentException("Key should have the same number of pairs as the bit length of the message digest: " + md.getDigestLength() * 8 + " but was " + v.length);
        }
        this.publicType = publicType;
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
    
    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder();
        sb.append(publicType ? "PublicKey" : "PrivateKey").append("(").append(getDigestAlgorithm()).append(")");
        if (publicType) {
            sb.append(" {\n");
            for (BigInteger[] v1 : v) {
                sb.append(" (");
                for (int j = 0; j < v1.length; j++) {
                    sb.append(String.format("%x", v1[j]));
                    if (j < v1.length - 1) {
                        sb.append(", ");
                    }
                }
                sb.append(")\n");
            }
            sb.append("}");
        }
        return sb.toString();
    }
    
    protected BigInteger[] selectBasedOnHash(BigInteger hash) { // TODO: change to take the message instead
        // TODO: assert bitlength
        
        byte[] bytes = hash.toByteArray();
        
        BigInteger[] s = new BigInteger[bytes.length * 8];
        
        for (int i = 0; i < bytes.length; i++) {
            byte b = bytes[i];
            boolean[] bb = toBooleanArray(b);
            //System.out.println("b: " + String.format("%x", b));
            //System.out.println("b: " + Arrays.toString(bb));
            
            for (int j = 0; j < 8; j++) {
                s[i * 8 + j] = bb[j] ? v[i * 8 + j][1] : v[i * 8 + j][0];
            }
        }
        return s;
    }

    protected static boolean[] toBooleanArray(byte b) {
        return new boolean[] {
            (b & 0x80) != 0,
            (b & 0x80 >> 1) != 0,
            (b & 0x80 >> 2) != 0,
            (b & 0x80 >> 3) != 0,
            (b & 0x80 >> 4) != 0,
            (b & 0x80 >> 5) != 0,
            (b & 0x80 >> 6) != 0,
            (b & (0x80 >> 7)) != 0,
        };
    }
    
    protected BigInteger hash(BigInteger value) {
        md.reset();
        byte[] digest = md.digest(value.toByteArray());
        return new BigInteger(digest);
    }
    
    protected byte[] hash(byte[] value) {
        md.reset();
        return md.digest(value);
    }
    
}
