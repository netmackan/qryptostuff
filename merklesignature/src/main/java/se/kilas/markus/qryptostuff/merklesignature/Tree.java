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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;

/**
 *
 * @author Markus Kilås
 */
public class Tree {
    private final ArrayList<ArrayList<Node>> nodes;
    private final Node top;

    public static Tree generate(final Hash[] hashes) {
        ArrayList<ArrayList<Node>> nodes = new ArrayList<>();
        // Leaves
        ArrayList<Node> a0 = new ArrayList<>();
        int j = 0;
        for (Hash h : hashes) {
            a0.add(new Node(0, j, h.getValue()));
            j++;
        }
        nodes.add(a0);
        // Nodes
        ArrayList<Node> prevLevel = a0;
        int length = prevLevel.size() / 2;
        for (int i = 1; length > 0; i++, length /= 2) {
            ArrayList<Node> nextLevel = new ArrayList<>();
            for (j = 0; j < length; j++) {
                nextLevel.add(new Node(i, j, prevLevel.get(j * 2), prevLevel.get(j * 2 + 1), null));
            }
            nodes.add(nextLevel);
            prevLevel = nextLevel;
        }
        return new Tree(nodes, nodes.get(nodes.size() - 1).get(0));
    }

    private Tree(ArrayList<ArrayList<Node>> nodes, Node top) {
        this.nodes = nodes;
        this.top = top;
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
    
}
