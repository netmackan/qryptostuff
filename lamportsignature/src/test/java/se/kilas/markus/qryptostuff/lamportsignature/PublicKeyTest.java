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

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Markus Kilås
 */
public class PublicKeyTest {
    
    public PublicKeyTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() {
    }
    
    @After
    public void tearDown() {
    }


    @Test
    public void testGenerateSignVerifySHA1() throws Exception {
        System.out.println("testGenerateSignVerifySHA1");
        generateSignAndVerify("SHA1");
    }

    @Test
    public void testGenerateSignVerifySHA256() throws Exception {
        System.out.println("testGenerateSignVerifySHA256");
        generateSignAndVerify("SHA-256");
    }
    
    @Test
    public void testGenerateSignVerifySHA384() throws Exception {
        System.out.println("testGenerateSignVerifySHA384");
        generateSignAndVerify("SHA-384");
    }
    
    @Test
    public void testGenerateSignVerifySHA512() throws Exception {
        System.out.println("testGenerateSignVerifySHA512");
        generateSignAndVerify("SHA-512");
    }

    private void generateSignAndVerify(final String digestAlgorithm) throws Exception {
        long start;
        
        // Key generation
        start = System.currentTimeMillis();
        PrivateKey priv = PrivateKey.generate(MessageDigest.getInstance(digestAlgorithm), new SecureRandom());
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
            signed = priv.sign(message);
            System.out.println("Signature: " + toHexArray(signed));
            System.out.println("Signing took " + (System.currentTimeMillis() - start) + " ms");
            System.out.println();
        }
        
        // Verifying ok
        {
            start = System.currentTimeMillis();
            boolean ok = pub.verify(message, signed);
            System.out.println("Signature ok: " + ok);
            System.out.println("Verifying took " + (System.currentTimeMillis() - start) + " ms");
            System.out.println();
            assertTrue("consistent signature", ok);
        }
        
        // Verifying modified
        final byte[] message2 = "Lillan gick på välen".getBytes("UTF-8");
        System.out.println("Message: " + new String(message2, "UTF-8"));
        {
            start = System.currentTimeMillis();
            boolean ok = pub.verify(message2, signed);
            System.out.println("Signature ok: " + ok);
            System.out.println("Verifying took " + (System.currentTimeMillis() - start) + " ms");
            System.out.println();
            assertFalse("inconsistent signature", ok);
        }
        
        // Trying to signHash twice with the same key
        try {
            start = System.currentTimeMillis();
            signed = priv.sign(message);
            System.out.println("Signature: " + Arrays.deepToString(signed));
            System.out.println("Signing took " + (System.currentTimeMillis() - start) + " ms");
            System.out.println();
            fail("Should have failed!");
        } catch (IllegalStateException ex) {
            System.out.println("Got expected: " + ex.getMessage());
        }
        
    }

    private static String toHexArray(byte[][] signed) {
        final StringBuilder sb = new StringBuilder();
        for (byte[] bytes : signed) {
            sb.append(Hex.toHexString(bytes)).append("\n");
        }
        return sb.toString();
    }
    
}
