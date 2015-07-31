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
package se.kilas.markus.qryptostuff.onetimesignature.lamport;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Markus Kilås
 */
public class LamportKeyTest {

    /**
     * Test of selectBasedOnHash method, of class LamportKey.
     * @throws java.lang.Exception
     */
    @Test
    public void testSelectBasedOnHash() throws Exception {
        System.out.println("selectBasedOnHash");
        
        LamportKey instance = new KeyImpl(new MessageDigestImpl(2), new byte[][][] {
            new byte[][] { Hex.decode("aa00"), Hex.decode("bb00") } ,
            new byte[][] { Hex.decode("aa01"), Hex.decode("bb01") } ,
            new byte[][] { Hex.decode("aa02"), Hex.decode("bb02") } ,
            new byte[][] { Hex.decode("aa03"), Hex.decode("bb03") } ,
            new byte[][] { Hex.decode("aa04"), Hex.decode("bb04") } ,
            new byte[][] { Hex.decode("aa05"), Hex.decode("bb05") } ,
            new byte[][] { Hex.decode("aa06"), Hex.decode("bb06") } ,
            new byte[][] { Hex.decode("aa07"), Hex.decode("bb07") } ,
            new byte[][] { Hex.decode("aa10"), Hex.decode("bb10") } ,
            new byte[][] { Hex.decode("aa11"), Hex.decode("bb11") } ,
            new byte[][] { Hex.decode("aa12"), Hex.decode("bb12") } ,
            new byte[][] { Hex.decode("aa13"), Hex.decode("bb13") } ,
            new byte[][] { Hex.decode("aa14"), Hex.decode("bb14") } ,
            new byte[][] { Hex.decode("aa15"), Hex.decode("bb15") } ,
            new byte[][] { Hex.decode("aa16"), Hex.decode("bb16") } ,
            new byte[][] { Hex.decode("aa17"), Hex.decode("bb17") } ,
        });
        
        assertEquals("aa00aa01aa02aa03aa04aa05aa06aa07aa10aa11aa12aa13aa14aa15aa16aa17", Hex.toHexString(flatten(instance.selectBasedOnHash(Hex.decode("0000"))))); // 000000000000000
        assertEquals("aa00bb01aa02bb03aa04bb05aa06bb07bb10aa11bb12aa13bb14aa15bb16aa17", Hex.toHexString(flatten(instance.selectBasedOnHash(Hex.decode("55aa"))))); // 0101010110101010
        assertEquals("bb00aa01bb02aa03bb04aa05bb06aa07aa10bb11aa12bb13aa14bb15aa16bb17", Hex.toHexString(flatten(instance.selectBasedOnHash(Hex.decode("aa55"))))); // 1010101001010101
        assertEquals("bb00bb01bb02bb03bb04bb05bb06bb07bb10bb11bb12bb13bb14bb15bb16bb17", Hex.toHexString(flatten(instance.selectBasedOnHash(Hex.decode("ffff"))))); // 1111111111111111
    }
    
    private static byte[] flatten(byte[][] byteArrays) throws IOException {
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        for (byte[] b : byteArrays) {
            bout.write(b);
        }
        return bout.toByteArray();
    }

    public class KeyImpl extends LamportKey {

        public KeyImpl(MessageDigest md, byte[][][] v) {
            super(v, md);
        }
    }

    public class MessageDigestImpl extends MessageDigest {

        private final int length;
        
        protected MessageDigestImpl(int length) {
            super("DUMMYALG");
            this.length = length;
        }

        @Override
        protected int engineGetDigestLength() {
            return length;
        }
        
        @Override
        protected void engineUpdate(byte input) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        protected void engineUpdate(byte[] input, int offset, int len) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        protected byte[] engineDigest() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        protected void engineReset() {
            throw new UnsupportedOperationException("Not supported yet.");
        }
        
    }
}
