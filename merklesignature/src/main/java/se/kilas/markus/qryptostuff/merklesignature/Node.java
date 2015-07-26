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

/**
 *
 * @author Markus Kilås
 */
public class Node {
    private final int i;
    private final int j;
    private final Node left;
    private final Node right;
    private final Hash value;
    
    public Node(final int i, final int j, final Hash value) {
        this(i, j, null, null, value);
    }

    public Node(final int i, final int j, final Node left, final Node right, final Hash value) {
        this.i = i;
        this.j = j;
        this.left = left;
        this.right = right;
        this.value = value;
    }

    public int getI() {
        return i;
    }

    public int getJ() {
        return j;
    }

    public Node getLeft() {
        return left;
    }

    public Node getRight() {
        return right;
    }

    public Hash getValue() {
        return value;
    }
    
    @Override
    public String toString() {
        //return "xYx";
        return String.format("a[%1d,%2d]", i, j); // XXX: Assumes max 10 levels
    }

    public String toOneLineString() {
        final StringBuilder sb = new StringBuilder();
        sb.append("a[").append(i).append(",").append(j);
        if (left != null || right != null) {
            sb.append(",").append(left == null ? "null" : left.toOneLineString()).append(",").append(right == null ? "null" : right.toOneLineString());
        }
        sb.append("]");
        return sb.toString();
    }
    
}
