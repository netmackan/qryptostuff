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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import org.bouncycastle.util.encoders.Hex;
import se.kilas.markus.qryptostuff.onetimesignature.OTSKeyPair;
import se.kilas.markus.qryptostuff.onetimesignature.OTSKeyPairGenerator;
import se.kilas.markus.qryptostuff.onetimesignature.OTSPrivateKey;
import se.kilas.markus.qryptostuff.onetimesignature.OTSPublicKey;

/**
 *
 * @author Markus Kilås
 */
public class MerkleTree {
    
    private final int num;
    private final OTSPrivateKey[] X;
    private final OTSPublicKey[] Y;
    private final ArrayList<ArrayList<Node>> nodes;
    private final Node top;
    private int keyIndex = 1; // Note: state
    private final int numLevels;
    private final MessageDigest md;

    public static MerkleTree generate(final int N, final OTSKeyPairGenerator keyGen, final MessageDigest md) {
        
        OTSPrivateKey[] X = new OTSPrivateKey[N];
        OTSPublicKey[] Y = new OTSPublicKey[N];
        Hash[] H = new Hash[N];
        for (int i = 0; i < N; i++) {
            OTSKeyPair keyPair = keyGen.generate();
            X[i] = keyPair.getPrivateKey();
            Y[i] = keyPair.getPublicKey();
            H[i] = new Hash(Y[i].hashKey(), "Y[" + i + "]");
            System.out.println("H[" + i + "] = " + H[i] + " = " + Hex.toHexString(H[i].getValue()));
        }
        
        ArrayList<ArrayList<Node>> nodes = new ArrayList<>();
        // Leaves
        ArrayList<Node> a0 = new ArrayList<>();
        int j = 0;
        for (Hash h : H) {
            a0.add(new Node(0, j, h));
            j++;
        }
        nodes.add(a0);
        // Nodes
        ArrayList<Node> prevLevel = a0;
        int length = prevLevel.size() / 2;
        for (int i = 1; length > 0; i++, length /= 2) {
            ArrayList<Node> nextLevel = new ArrayList<>();
            for (j = 0; j < length; j++) {
                Node left = prevLevel.get(j * 2);
                Node right = prevLevel.get(j * 2 + 1);
                nextLevel.add(new Node(i, j, left, right, Hash.concat(left.getValue(), right.getValue(), md)));
            }
            nodes.add(nextLevel);
            prevLevel = nextLevel;
        }
        return new MerkleTree(N, X, Y, nodes, nodes.get(nodes.size() - 1).get(0), md);
    }

    private MerkleTree(int num, OTSPrivateKey[] X, OTSPublicKey[] Y, ArrayList<ArrayList<Node>> nodes, Node top, MessageDigest md) {
        this.num = num;
        this.X = X;
        this.Y = Y;
        this.nodes = nodes;
        this.top = top;
        this.numLevels = nodes.size();
        this.md = md;
    }

    public Node getTop() {
        return top;
    }

    @Override
    public String toString() {
        return "Tree:" + getTop().toOneLineString();
    }

    /**
     * Formatting:
     * <pre><![CDATA[
     * L                       indent1   indent2
     * 3: --------X--------    1<<3=8    1<<4-1=15    8-8
     * 2: ----X-------X----    1<<2=4    1<<3-1=7    4-7-4
     * 1: --X---X---X---X--    1<<1=2    1<<2-1=3    2-3-2
     * 0: -X-X-X-X-X-X-X-X-    1<<0=1    1<<1-1=1    0-1-0
     *
     *
     * indent1: 1 << L
     * indent2: 1 << (L+1) - 1
     *
     * ]]></pre>
     * @return
     */
    public String toTreeString() {
        final int nodeWidth = top.toString().length();
        final char space = ' '; // '-';
        final char nl = '\n';
        final StringBuilder sb = new StringBuilder();
        sb.append("Tree{\n");
        ArrayList<ArrayList<Node>> reversedNodes = new ArrayList<>(nodes);
        Collections.reverse(reversedNodes);
        int level = reversedNodes.size() - 1;
        for (ArrayList<Node> nodesAtLevel : reversedNodes) {
            char[] indent1 = new char[nodeWidth * ((1 << (level)) - 1) + 1];
            Arrays.fill(indent1, space);
            char[] indent2 = new char[nodeWidth * ((1 << (level + 1)) - 1)];
            Arrays.fill(indent2, space);
            sb.append(new String(indent1));
            final Iterator<Node> niter = nodesAtLevel.iterator();
            while (niter.hasNext()) {
                sb.append(niter.next());
                if (niter.hasNext()) {
                    sb.append(indent2);
                }
            }
            char[] newLines = new char[level + 2];
            Arrays.fill(newLines, nl);
            sb.append(indent1).append(newLines);
            level--;
        }
        sb.append("}");
        return sb.toString();
    }
    
    public MerkleSig sign(final byte[] message) throws IllegalStateException {
        if (++keyIndex >= num) {
            throw new IllegalStateException("No more signatures available");
        }
        
        OTSPrivateKey privateKey = X[keyIndex];
        OTSPublicKey publicKey = Y[keyIndex];
        byte[][] sigPrim = privateKey.sign(message);
        
        //
        int i = keyIndex;
        
        // Find path A from a0,i to the root
        Node auth[] = new Node[numLevels - 1];
        
        Node A0 = nodes.get(0).get(i);
        System.out.println("A[0] = " + A0);
        for (int j = 1; j < numLevels; j++) {
            Node A_i;
            Node Auth_i;
            if (i % 2 == 0) { // Left side
                i = i / 2;
                A_i = nodes.get(j).get(i);
                Auth_i = A_i.getRight();
            } else { // Right side
                i = (i - 1) / 2;
                A_i = nodes.get(j).get(i);
                Auth_i = A_i.getLeft();
            }
            
            System.out.println("A[" + j + "] = " + A_i + ", auth_" + (j - 1) + " = " + Auth_i);
            auth[j - 1] = Auth_i;
        }
        
        System.out.println(Arrays.toString(auth));
        
        byte[][] authsBytes = new byte[auth.length][];
        for (int j = 0; j < authsBytes.length; j++) {
            authsBytes[j] = auth[j].getValue().getValue();
        }
        
        return new MerkleSig(sigPrim, publicKey, keyIndex, authsBytes, md.getAlgorithm());
    }
    
}
