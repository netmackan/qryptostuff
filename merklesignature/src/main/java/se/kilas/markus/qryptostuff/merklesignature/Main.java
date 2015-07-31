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

import java.security.MessageDigest;
import java.util.Random;
import org.bouncycastle.util.encoders.Hex;
import se.kilas.markus.qryptostuff.onetimesignature.lamport.LamportKeyPairGenerator;
import se.kilas.markus.qryptostuff.onetimesignature.OTSKeyPairGenerator;

/**
 *
 * @author Markus Kilås
 */
public class Main {
    public static void main(String[] args) throws Exception {
        System.out.println("MerkleSignature");
        
        
        System.out.println();
        System.out.println("*** Key generation ***");
        
        // Number of messages
        final int n = 3;
        final int N = 1 << n;
        System.out.println("N = 2^n = 2^" + n + " = " + N);
        System.out.println();
        
        // Generating keys
        final MessageDigest md = MessageDigest.getInstance("MD5"); // XXX: Weak alg!
        final Random random = new Random(1234); // XXX: Not SecureRandom and uses static seed!
        final OTSKeyPairGenerator keyGen = new LamportKeyPairGenerator(md, random);
        MerkleTree tree = MerkleTree.generate(N, keyGen, md);
        System.out.println(tree);
        System.out.println();
        System.out.println(tree.toTreeString());
        final byte[] publicKey = tree.getTop().getValue().getValue();
        System.out.println("Public key: " + Hex.toHexString(publicKey));
        
        System.out.println();
        System.out.println("*** Signature generation ***");
        
        // Message
        final byte[] message1 = "Lillan gick på vägen".getBytes("UTF-8");
        System.out.println("Message1: " + new String(message1, "UTF-8"));
        System.out.println();
        
        // Signature generation
        MerkleSig sig = tree.sign(message1);
        System.out.println("sig = " + sig);
        System.out.println();
        
        System.out.println("*** Signature verification ***");
        boolean ok = sig.verify(message1, publicKey);
        System.out.println("Merkle signature ok: " + ok);
        
        final byte[] message2 = "Lillan gick ur vägen".getBytes("UTF-8");
        System.out.println("Message2: " + new String(message1, "UTF-8"));
        ok = sig.verify(message2, publicKey);
        System.out.println("message1==message2: " + ok);
        
    }
        
}
