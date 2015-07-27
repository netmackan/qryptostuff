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
package se.kilas.markus.qryptostuff.merklesignature;

import org.bouncycastle.util.encoders.Hex;
import se.kilas.markus.qryptostuff.onetimesignature.OTSPublicKey;

/**
 *
 * @author Markus Kilås
 */
public class MerkleSig {
    private final byte[][] sigPrim;
    private final OTSPublicKey publicKey; // TODO: Not according to spec but reciever needs to get it from somewhere(?)
    private final int index; // TODO: maybe there is an alternative solution to this
    private final byte[][] auth;

    public MerkleSig(byte[][] sigPrim, OTSPublicKey publicKey, int index, byte[][] auth) {
        this.sigPrim = sigPrim;
        this.publicKey = publicKey;
        this.index = index;
        this.auth = auth;
    }

    public byte[][] getSigPrim() {
        return sigPrim;
    }

    public byte[][] getAuth() {
        return auth;
    }

    public OTSPublicKey getPublicKey() {
        return publicKey;
    }
    
    public int getIndex() {
        return index;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder();
        sb.append("MerkleSig{");
        sb.append("sigPrim=").append(toHexArray(sigPrim)).append(", ");
        sb.append("index=").append(index).append(", ");
        int i = 0;
        for (byte[] authi : auth) {
            sb.append("auth_").append(i++).append("=").append(Hex.toHexString(authi)).append(", ");
        }
        sb.append("}");
        return sb.toString();
    }
    
    private static String toHexArray(byte[][] signed) {
        final StringBuilder sb = new StringBuilder();
        for (byte[] bytes : signed) {
            sb.append(Hex.toHexString(bytes)).append("\n");
        }
        return sb.toString();
    }
}
