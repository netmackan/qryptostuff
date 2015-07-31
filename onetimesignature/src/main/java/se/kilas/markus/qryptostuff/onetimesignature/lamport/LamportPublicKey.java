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
import java.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import se.kilas.markus.qryptostuff.onetimesignature.OTSPublicKey;

/**
 *
 * @author Markus Kilås
 */
public class LamportPublicKey extends LamportKey implements OTSPublicKey {
    
    public LamportPublicKey(byte[][][] z, MessageDigest md) {
        super(z, md);
    }

    @Override
    public boolean verify(byte[] message, byte[][] signed) {
        byte[][] picked = selectBasedOnHash(hash(message));
        
        byte[][] signedAndHashed = new byte[signed.length][];
        for (int i = 0; i < signed.length; i++) {
            signedAndHashed[i] = hash(signed[i]);
        }

        return Arrays.deepEquals(picked, signedAndHashed);
    }
    
    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder();
        sb.append("PublicKey").append("(").append(getDigestAlgorithm()).append(")");
        sb.append(" {\n");
        for (byte[][] v1 : v) {
            for (byte[] v11 : v1) {
                sb.append(Hex.toHexString(v11)).append("\n");
            }
        }
        sb.append("}");
        return sb.toString();
    }
}
