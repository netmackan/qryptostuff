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
package se.kilas.markus.qryptostuff.onetimesignature;

/**
 *
 * @author Markus Kilås
 */
public class OTSKeyPair {
    private final OTSPrivateKey privateKey;
    private final OTSPublicKey publicKey;

    public OTSKeyPair(OTSPrivateKey privateKey, OTSPublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }
    
    public OTSPrivateKey getPrivateKey() {
        return privateKey;
    }
    
    public OTSPublicKey getPublicKey() {
        return publicKey;
    }

    @Override
    public String toString() {
        return "OTSKeyPair{" + "privateKey=" + privateKey + ", publicKey=" + publicKey + '}';
    }
    
}
