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
import se.kilas.markus.qryptostuff.onetimesignature.OTSKeyPair;
import se.kilas.markus.qryptostuff.onetimesignature.OTSKeyPairGenerator;

/**
 *
 * @author Markus Kilås
 */
public class LamportKeyPairGenerator implements OTSKeyPairGenerator {

    private final MessageDigest md;
    private final Random random;
    
    public LamportKeyPairGenerator(final MessageDigest md, final Random random) {
        this.md = md;
        this.random = random;
    }
    
    @Override
    public OTSKeyPair generate() {
        final LamportPrivateKey privateKey = LamportPrivateKey.generate(md, random);
        final LamportPublicKey publicKey = privateKey.derivePublic();
        return new OTSKeyPair(privateKey, publicKey);
    }
    
}
