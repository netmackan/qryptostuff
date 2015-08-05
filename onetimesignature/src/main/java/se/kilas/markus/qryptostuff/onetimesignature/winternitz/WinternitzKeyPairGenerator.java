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

import java.security.MessageDigest;
import java.util.Random;
import se.kilas.markus.qryptostuff.onetimesignature.OTSKeyPair;
import se.kilas.markus.qryptostuff.onetimesignature.OTSKeyPairGenerator;

/**
 *
 * @author Markus Kilås
 */
public class WinternitzKeyPairGenerator implements OTSKeyPairGenerator {

    private final MessageDigest md;
    private final Random random;
    private final int paramW;

    public WinternitzKeyPairGenerator(final MessageDigest md, final Random random, final int paramW) {
        this.md = md;
        this.random = random;
        this.paramW = paramW;
        if (paramW < 2) {
            throw new IllegalArgumentException("w must be >= 2");
        }
    }

    @Override
    public OTSKeyPair generate() {
        final int s = md.getDigestLength() * 8;
        final int t = s / paramW + (WinternitzKey.log2(s / paramW) + 1 + paramW) / paramW; // TODO: Move into WinternitzPrivateKey
        System.out.println("s = " + s);
        System.out.println("t = " + t);
                
        final WinternitzPrivateKey privateKey = WinternitzPrivateKey.generate(md, random, paramW, t);
        final WinternitzPublicKey publicKey = privateKey.derivePublic();
        return new OTSKeyPair(privateKey, publicKey);
    }

}
