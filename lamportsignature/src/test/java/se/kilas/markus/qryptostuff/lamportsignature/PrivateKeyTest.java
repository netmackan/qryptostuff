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

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
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
public class PrivateKeyTest {
    
    public PrivateKeyTest() {
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


    /**
     * Test of sign method, of class PrivateKey.
     */
    @Test
    public void testSign() throws NoSuchAlgorithmException {
        System.out.println("sign");
        
        BigInteger hash = new BigInteger("0001000110100010", 2);
        System.out.println("hash.hex: " + hash.toString(16));
        System.out.println("hash.len: " + hash.toByteArray().length);
        
        final PrivateKey p = PrivateKey.generate(MessageDigest.getInstance("MD5"), new SecureRandom(new byte[] { (byte) 0 }));
        
        // Manually setup the expected result for 0001000110100010
        BigInteger[] expResult = new BigInteger[] {
            p.v[0][0], p.v[1][0], p.v[2][0], p.v[3][1], p.v[4][0], p.v[5][0], p.v[6][0], p.v[7][1], p.v[8][1], p.v[9][0], p.v[10][1], p.v[11][0], p.v[12][0], p.v[13][0], p.v[14][1], p.v[15][0]
        };
        
        // Sign
        BigInteger[] result = p.sign(hash);

        assertArrayEquals(expResult, result);
    }
    
    @Test
    public void testToBinaryArray() throws Exception {
        assertEquals("00000000", booleanArrayToString(PrivateKey.toBooleanArray((byte) 0x0)));
        assertEquals("00000001", booleanArrayToString(PrivateKey.toBooleanArray((byte) 0x1)));
        assertEquals("00000010", booleanArrayToString(PrivateKey.toBooleanArray((byte) 0x2)));
        assertEquals("00000011", booleanArrayToString(PrivateKey.toBooleanArray((byte) 0x3)));
        assertEquals("00000100", booleanArrayToString(PrivateKey.toBooleanArray((byte) 0x4)));
        assertEquals("00000101", booleanArrayToString(PrivateKey.toBooleanArray((byte) 0x5)));
        assertEquals("00000110", booleanArrayToString(PrivateKey.toBooleanArray((byte) 0x6)));
        assertEquals("00000111", booleanArrayToString(PrivateKey.toBooleanArray((byte) 0x7)));
        assertEquals("00001000", booleanArrayToString(PrivateKey.toBooleanArray((byte) 0x8)));
        assertEquals("11111010", booleanArrayToString(PrivateKey.toBooleanArray((byte) 0xfa)));
        assertEquals("11001110", booleanArrayToString(PrivateKey.toBooleanArray((byte) 0xce)));
        assertEquals("11111111", booleanArrayToString(PrivateKey.toBooleanArray((byte) 0xff)));
    }
    
    private String booleanArrayToString(boolean[] bs) {
        final StringBuilder sb = new StringBuilder();
        for (boolean b : bs) {
            sb.append(b ? "1" : "0");
        }
        return sb.toString();
    }
    
}
