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
package se.kilas.markus.qryptostuff.lamportsignature.jce;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Constructor;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import se.kilas.markus.qryptostuff.lamportsignature.LamportPrivateKey;

/**
 *
 * @author Markus Kilås
 */
public class LamportProvider extends Provider {

    public static final String NAME = "Lamport";
    
    public LamportProvider() {
        super(NAME, 0.1, "Lamport Signature Provider");
        putService(new LamportSigningService
            (this, "Signature", "SHA1withLamport", LamportSignature.class.getName()));
    }
    
    private static class MyService extends Service {

        private static final Class[] paramTypes = {Provider.class, String.class};

        MyService(Provider provider, String type, String algorithm,
                String className) {
            super(provider, type, algorithm, className, null, null);
        }

        @Override
        public Object newInstance(Object param) throws NoSuchAlgorithmException {
            try {
                // get the Class object for the implementation class
                Class clazz;
                Provider provider = getProvider();
                ClassLoader loader = provider.getClass().getClassLoader();
                if (loader == null) {
                    clazz = Class.forName(getClassName());
                } else {
                    clazz = loader.loadClass(getClassName());
                }
                // fetch the (Provider, String) constructor
                Constructor cons = clazz.getConstructor(paramTypes);
                // invoke constructor and return the SPI object
                Object obj = cons.newInstance(new Object[] {provider, getAlgorithm()});
                return obj;
            } catch (Exception e) {
                e.printStackTrace();
                throw new NoSuchAlgorithmException("Could not instantiate service", e);
            }
        }
    }

    private static class LamportSigningService extends MyService {

        LamportSigningService(Provider provider, String type, String algorithm,
                String className) {
            super(provider, type, algorithm, className);
        }
        // we override supportsParameter() to let the framework know which
        // keys we can support. We support instances of MySecretKey, if they
        // are stored in our provider backend, plus SecretKeys with a RAW encoding.
        @Override
        public boolean supportsParameter(Object obj) {
            if (obj instanceof JceLamportPrivateKey == false) {
                /*if (LOG.isDebugEnabled())*/ {
                    final StringBuilder sb = new StringBuilder();
                    sb.append("Not our object:\n")
                            .append(obj)
                            .append(", classloader: ")
                            .append(obj.getClass().getClassLoader())
                            .append(" (").append(this.getClass().getClassLoader().hashCode()).append(")")
                            .append("\n");
                    sb.append("We are:\n")
                            .append(this)
                            .append(", classloader: ")
                            .append(this.getClass().getClassLoader())
                            .append(" (").append(this.getClass().getClassLoader().hashCode()).append(")")
                            .append("\n");
                    System.err.println(sb.toString());
                }
                return false;
            }
            PrivateKey key = (PrivateKey)obj;
//            if (key.getAlgorithm().equals(getAlgorithm()) == false) {
//                return false;
//            }
            if (key instanceof JceLamportPrivateKey) {
//                NJI11StaticSessionPrivateKey myKey = (NJI11StaticSessionPrivateKey)key;
//                return myKey.provider == getProvider();
                return true; // TODO: for now...
            }/* else {
                return "RAW".equals(key.getFormat());
            }*/
            return false;
        }
    }
    
    static class LamportKeyPairGenerator extends KeyPairGeneratorSpi {

        private MessageDigest md;
        private SecureRandom random;
        
        @Override
        public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
            if (!(params instanceof LamportAlgorithmParameterSpec)) {
                throw new IllegalArgumentException("Expected LamportAlgorithmParameterSpec");
            }
            
            try {
                md = MessageDigest.getInstance(((LamportAlgorithmParameterSpec) params).getDigestAlgorithm());
            }
            catch (NoSuchAlgorithmException ex) {
                throw new InvalidAlgorithmParameterException(ex);
            }
            this.random = random;
        }

                
        @Override
        public void initialize(int keysize, SecureRandom random) {
            throw new UnsupportedOperationException();
        }

        @Override
        public KeyPair generateKeyPair() {
            LamportPrivateKey priv = LamportPrivateKey.generate(md, random);
            throw new UnsupportedOperationException("Not yet implemented");
            /*PrivateKey pk = new JceLamportPrivateKey(priv);
            PublicKey pubKey = new JceLamportPublicKey(priv.derivePublic());
            return new KeyPair(pubKey, pk);*/
        }
        
    }
    
    /*private*/ static class LamportSignature extends SignatureSpi {
        private final LamportProvider provider;
        private final String algorithm;
        private int opmode;
        private JceLamportPrivateKey myKey;
        private long session;
        
        private ByteArrayOutputStream buffer;
        public LamportSignature(Provider provider, String algorithm) {
            super();
            this.provider = (LamportProvider)provider;
            this.algorithm = algorithm;
        }
//        protected void engineInit(int opmode, Key key, SecureRandom random)
//                throws InvalidKeyException {
//            this.opmode = opmode;
//            myKey = MySecretKey.getKey(provider, algorithm, key);
//            if (myKey == null) {
//                throw new InvalidKeyException();
//            }
//            buffer = new ByteArrayOutputStream();
//        }
//        protected byte[] engineUpdate(byte[] b, int ofs, int len) {
//            buffer.write(b, ofs, len);
//            return new byte[0];
//        }
//        protected int engineUpdate(byte[] b, int ofs, int len, byte[] out, int outOfs) {
//            buffer.write(b, ofs, len);
//            return 0;
//        }
//        protected byte[] engineDoFinal(byte[] b, int ofs, int len) {
//            buffer.write(b, ofs, len);
//            byte[] in = buffer.toByteArray();
//            byte[] out;
//            if (opmode == Cipher.ENCRYPT_MODE) {
//                out = provider.cryptoBackend.encrypt(algorithm, myKey.handle, in);
//            } else {
//                out = provider.cryptoBackend.decrypt(algorithm, myKey.handle, in);
//            }
//            buffer = new ByteArrayOutputStream();
//            return out;
//        }
        // code for remaining CipherSpi methods goes here

        @Override
        protected void engineInitVerify(PublicKey pk) throws InvalidKeyException {
            throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        }

        @Override
        protected void engineInitSign(PrivateKey pk) throws InvalidKeyException {
            
            /***if (pk instanceof NJI11Object == false) {
                throw new InvalidKeyException("Not an NJI11Object: " + pk);
            }
            myKey = (NJI11Object) pk;
            
            if (pk instanceof NJI11StaticSessionPrivateKey) {
                session = ((NJI11StaticSessionPrivateKey) pk).getSession();
            } else {
                session = myKey.getSlot().aquireSession();
            }
            
            buffer = new ByteArrayOutputStream();
            CE.SignInit(session, new CKM(CKM.SHA1_RSA_PKCS, new byte[0]), myKey.getObject());
            * **/
            
            throw new UnsupportedOperationException("Implement initSign");
        }

        @Override
        protected void engineUpdate(byte b) throws SignatureException {
//            CE.SignUpdate(myKey.getSession(), new byte[] {b});
            buffer.write(b);
        }

        @Override
        protected void engineUpdate(byte[] bytes, int offset, int length) throws SignatureException {
            buffer.write(bytes, offset, length);
            
//            for (int i = offset; i < offset+length; i++) {
//                engineUpdate(bytes[i]);  // TODO: Inefficent implementation
//            }
        }

        @Override
        protected byte[] engineSign() throws SignatureException {
            /*final byte[] result = CE.Sign(session, buffer.toByteArray());
            if (myKey instanceof NJI11ReleasebleSessionPrivateKey) {
                myKey.getSlot().releaseSession(session);
            }
            return result;*/
            throw new UnsupportedOperationException("Implement initSign");
        }

        @Override
        protected boolean engineVerify(byte[] bytes) throws SignatureException {
            throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        }

        @Override
        protected void engineSetParameter(String string, Object o) throws InvalidParameterException {
            throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        }

        @Override
        protected Object engineGetParameter(String string) throws InvalidParameterException {
            throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        }
    }
}
