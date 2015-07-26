/*
 * Copyright (C) 2015 user
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

/**
 *
 * @author user
 */
public class MerkleSig {
    private final byte[][] sigPrim;
    private final byte[][] auth;

    public MerkleSig(byte[][] sigPrim, byte[][] auth) {
        this.sigPrim = sigPrim;
        this.auth = auth;
    }

    public byte[][] getSigPrim() {
        return sigPrim;
    }

    public byte[][] getAuth() {
        return auth;
    }
    
    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder();
        sb.append("MerkleSig{");
        sb.append("sigPrim=").append(toHexArray(sigPrim)).append(", ");
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
