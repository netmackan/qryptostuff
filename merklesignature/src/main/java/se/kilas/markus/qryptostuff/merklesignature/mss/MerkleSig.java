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
package se.kilas.markus.qryptostuff.merklesignature.mss;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
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
    private final String hashAlgorithm;

    public MerkleSig(byte[][] sigPrim, OTSPublicKey publicKey, int index, byte[][] auth, String hashAlgorithm) {
        this.sigPrim = sigPrim;
        this.publicKey = publicKey;
        this.index = index;
        this.auth = auth;
        this.hashAlgorithm = hashAlgorithm;
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

    public String getHashAlgorithm() {
        return hashAlgorithm;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder();
        sb.append("MerkleSig{");
        sb.append("sigPrim=").append(toHexArray(sigPrim)).append(", ");
        sb.append("index=").append(index).append(", ");
        sb.append("hashAlgorithm=").append(hashAlgorithm).append(", ");
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

    public boolean verify(byte[] message1, byte[] masterPublicKey) throws NoSuchAlgorithmException {
        
        boolean ok = publicKey.verify(message1, sigPrim);
        System.out.println("sigPrim ok: " + ok);
        if (!ok) {
            System.out.println("Signature verification failed!");
            return false;
        } else {
            MessageDigest md = MessageDigest.getInstance(hashAlgorithm);
            
            Hash A0 = new Hash(publicKey.hashKey(), "A0");
            System.out.println("A[0] = " + A0);

            int i = index;

            Hash Ai = A0;
            for (int j = 0; j < auth.length; j++) {
                if (i % 2 == 0) {
                    Ai = Hash.concat(Ai, new Hash(auth[j], "auth" + j), md);
                    i = i / 2;
                } else {
                    Ai = Hash.concat(new Hash(auth[j], "auth" + j), Ai, md);
                    i = (i - 1) / 2;
                }
                System.out.println("A[" + (j + 1) + "] = " + Ai);
            }
            System.out.println("Ai=" + Ai + " = " + Hex.toHexString(Ai.getValue()));
            System.out.println("Public key =                    " + Hex.toHexString(masterPublicKey));
            boolean keyMatches = Arrays.equals(masterPublicKey, Ai.getValue());
            System.out.println("Matches: " + keyMatches);
            if (!keyMatches) {
                System.out.println("Signature verification failed!");
                return false;
            }
            return true;
        }

    }
}
