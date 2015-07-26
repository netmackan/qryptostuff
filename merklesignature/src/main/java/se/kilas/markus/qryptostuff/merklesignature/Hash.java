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

//import org.bouncycastle.util.encoders.Hex;

import java.security.MessageDigest;


/**
 *
 * @author Markus Kilås
 */
public class Hash {
    private final byte[] value;
    private final String name;

    public static Hash concat(Hash left, Hash right, MessageDigest md) {
        md.reset();
        md.update(left.value);
        md.update(right.value);
        return new Hash(md.digest(), left.name + "||" + right.name);
    }
    
    public Hash(final byte[] value, final String name) {
        this.value = value;
        this.name = name;
    }

    public byte[] getValue() {
        return this.value;
    }

    public String getName() {
        return name;
    }

    @Override
    public String toString() {
        return "H(" + name + ")";
        //return "Hash:" + Hex.toHexString(value);
    }
    
}
