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
import java.util.Arrays;

/**
 *
 * @author Markus Kilås
 */
public class PublicKey extends Key {
    
    public PublicKey(MessageDigest md, BigInteger[][] z) {
        super(true, md, z);
    }

    public boolean verify(byte[] digest, BigInteger[] signed) {
        BigInteger[] picked = selectBasedOnHash(new BigInteger(digest));
        
        BigInteger[] signedAndHashed = new BigInteger[signed.length];
        for (int i = 0; i < signed.length; i++) {
            signedAndHashed[i] = hash(signed[i]);
        }
        
        return Arrays.equals(picked, signedAndHashed);
    }
    
    public boolean verify(byte[] message, byte[][] signed) {
        BigInteger[] picked = selectBasedOnHash(new BigInteger(hash(message)));
        
        BigInteger[] signedAndHashed = new BigInteger[signed.length];
        for (int i = 0; i < signed.length; i++) {
            signedAndHashed[i] = hash(new BigInteger(signed[i]));
        }
        
        return Arrays.equals(picked, signedAndHashed);
    }
    
    
}
