/*
 * Copyright (C) 2015 user
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

import java.security.Security;
import java.security.Signature;
import se.kilas.markus.qryptostuff.lamportsignature.jce.LamportProvider;

/**
 *
 * @author user
 */
public class Main {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new LamportProvider());
        
        Signature sig = Signature.getInstance("SHA1withLamport");
        System.out.println("sig: " + sig);
        //sig.init
        
    }
}
