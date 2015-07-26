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
import java.security.SecureRandom;
import se.kilas.markus.qryptostuff.lamportsignature.LamportKeyPairGenerator;
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
        final MessageDigest md = MessageDigest.getInstance("MD5"); // XXX: Weak alg
        final SecureRandom random = new SecureRandom(new byte[] { 0 }); // XXX: static seed
        final OTSKeyPairGenerator keyGen = new LamportKeyPairGenerator(md, random);
        Tree tree = Tree.generate(N, keyGen, md);
        System.out.println(tree);
        System.out.println();
        
        
        System.out.println(tree.toTreeString());
    }
        
}
