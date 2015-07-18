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
package se.kilas.markus.qryptostuff.lamportsignature;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 *
 * @author Markus Kilås
 */
public class LamportSignatures1 {

    private static final String DIGEST_ALG = "SHA-512";
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws NoSuchAlgorithmException, UnsupportedEncodingException {
 
        long start;
        
        // Key generation
        start = System.currentTimeMillis();
        PrivateKey priv = PrivateKey.generate(MessageDigest.getInstance(DIGEST_ALG), new SecureRandom());
        System.out.println(priv);
        PublicKey pub = priv.derivePublic();
        System.out.println(pub);
        System.out.println("Key generation took " + (System.currentTimeMillis() - start) + " ms");
        System.out.println();
        
        // Message
        final byte[] message = "Lillan gick på vägen".getBytes("UTF-8");
        System.out.println("Message: " + new String(message, "UTF-8"));
        System.out.println();
        
        // Signing
        byte[][] signed;
        {
            start = System.currentTimeMillis();
            //MessageDigest md = MessageDigest.getInstance(DIGEST_ALG);
            //byte[] digest = md.digest(message);
            //System.out.println("Hashed message: " + new BigInteger(digest));
            //signed = priv.sign(new BigInteger(digest));
            signed = priv.sign(message);
            System.out.println("Signature: " + Arrays.deepToString(signed));
            System.out.println("Signing took " + (System.currentTimeMillis() - start) + " ms");
            System.out.println();
        }
        
        // Verifying ok
        {
            start = System.currentTimeMillis();
            //MessageDigest md = MessageDigest.getInstance(DIGEST_ALG);
            //byte[] digest = md.digest(message);
            //System.out.println("Hashed message: " + new BigInteger(digest));
            boolean ok = pub.verify(message, signed);
            System.out.println("Signature ok: " + ok);
            System.out.println("Verifying took " + (System.currentTimeMillis() - start) + " ms");
            System.out.println();
        }
        
        // Verifying modified
        final byte[] message2 = "Lillan gick på välen".getBytes("UTF-8");
        System.out.println("Message: " + new String(message2, "UTF-8"));
        {
            start = System.currentTimeMillis();
            //MessageDigest md = MessageDigest.getInstance(DIGEST_ALG); // TODO hardcoded
            //byte[] digest = md.digest(message2);
            //System.out.println("Hashed message: " + new BigInteger(digest));
            boolean ok = pub.verify(message2, signed);
            System.out.println("Signature ok: " + ok);
            System.out.println("Verifying took " + (System.currentTimeMillis() - start) + " ms");
            System.out.println();
        }
        
        // Trying to sign twice with the same key
        try {
            start = System.currentTimeMillis();
            //MessageDigest md = MessageDigest.getInstance(DIGEST_ALG);
            //byte[] digest = md.digest(message);
            //System.out.println("Hashed message: " + new BigInteger(digest));
            signed = priv.sign(message);
            System.out.println("Signature: " + Arrays.deepToString(signed));
            System.out.println("Signing took " + (System.currentTimeMillis() - start) + " ms");
            System.out.println("Should have failed!");
            System.out.println();
        } catch (IllegalStateException ex) {
            System.out.println("Got expected: " + ex.getMessage());
        }
        
    }
    
}
