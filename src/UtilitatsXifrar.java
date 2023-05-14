import javax.crypto.*;

import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.security.*;

import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import java.util.Arrays;
import java.util.Base64;

public class UtilitatsXifrar {

    // Genera una clau simètrica aleatòria de la mida especificada en bits
    public static SecretKey keygenKeyGeneration(int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keySize);
        return keyGen.generateKey();
    }

    // Genera una clau simètrica a partir d'una contrasenya i la mida especificada en bits
    public static SecretKey passwordKeyGeneration(String text, int keySize){
        SecretKey sKey = null;
        if ((keySize == 128)||(keySize == 192)||(keySize == 256)) {
            try {
                byte[] data = text.getBytes("UTF-8");
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] hash = md.digest(data);
                byte[] key = Arrays.copyOf(hash, keySize/8);
                sKey = new SecretKeySpec(key, "AES");
            } catch (Exception ex) {
                System.err.println("Error generant la clau:" + ex);
            }
        }
        return sKey;
    }

    // Xifra les dades amb la clau especificada
    public static byte[] encryptData(byte[] data, KeyPair key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key.getPublic());
        return cipher.doFinal(data);
    }

    // Desxifra les dades amb la clau especificada
    public static byte[] decryptData(byte[] data, KeyPair key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte [] decryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, key.getPrivate());
            decryptedData = cipher.doFinal(data);

        }
        catch (Exception e){
            System.err.println(e);
        }
        return decryptedData;
    }

    public static KeyPair randomGenerate(int len) {
        KeyPair keys = null;
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(len);
            keys = keyGen.genKeyPair();
        } catch (Exception ex) {
            System.err.println("Generador no disponible.");
        }
        return keys;
    }



    public static KeyStore loadKeyStore(String ksFile, String ksPwd) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        File f = new File (ksFile);
        if (f.isFile()) {
            FileInputStream in = new FileInputStream (f);
            ks.load(in, ksPwd.toCharArray());
        }
        return ks;
    }
    public static PublicKey getPublicKey(String fitxer) throws Exception {
        FileInputStream fis = new FileInputStream(fitxer);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
        return cert.getPublicKey();
    }
    public static PublicKey getPublicKey(KeyStore ks, String alias, String pwMyKey) throws Exception {
        Key key = ks.getKey(alias, pwMyKey.toCharArray()); // Descifra la clave privada con la contraseña de la clave simétrica
        if (!(key instanceof PrivateKey)) {
            throw new Exception("No se ha encontrado la clave privada para el alias: " + alias);
        }
        Certificate cert = ks.getCertificate(alias);
        if (cert == null) {
            throw new Exception("No se ha encontrado el certificado para el alias: " + alias);
        }
        PublicKey publicKey = cert.getPublicKey();
        return publicKey;

    }
    public static byte[] generateSignature(String data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withDSA", "SUN");
        signature.initSign(privateKey);
        signature.update(data.getBytes());
        byte[] sign = signature.sign();
        return sign;
    }

    public static boolean verifySignature(byte[] data, byte[] signature, PublicKey publicKey) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withDSA", "SUN");
        verifier.initVerify(publicKey);
        verifier.update(data);
        return verifier.verify(signature);
    }
    public static byte[][] encryptWrappedData(byte[] data, PublicKey pub) {
        byte[][] encWrappedData = new byte[2][];
        try {
            // Generamos la clau secreta simètrica
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            kgen.init(128); // Especificar la longitud de la clau, en aquest cas 128 bits
            SecretKey sKey = kgen.generateKey(); // Generar la clau simètrica
            Cipher cipher = Cipher.getInstance("AES"); // Usamos el algoritmo de xifrat asimetric
            cipher.init(Cipher.ENCRYPT_MODE, sKey); // Inicialitzar el Cipher amb la clau simètrica
            byte[] encMsg = cipher.doFinal(data); // Xifrem les dades

            // Embolcallar la clau simètrica amb la clau pública del receptor
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); // Crear un objecte Cipher per xifrar la clau simètrica
            cipher.init(Cipher.WRAP_MODE, pub); // Inicialitzar el Cipher amb la clau pública del receptor en mode embolcallament
            byte[] encKey = cipher.wrap(sKey); // Embolcallar la clau simètrica

            // Retornar les dades xifrades i la clau embolcallada
            encWrappedData[0] = encMsg;
            encWrappedData[1] = encKey;
        } catch (Exception  ex) {
            System.err.println("Ha succeït un error xifrant: " + ex);
        }
        return encWrappedData;
    }

    public static byte[] decryptWrappedData(byte[][] encWrappedData, PrivateKey priv) {
        try {
            // Obtenemos el mensaje cifrado y la clave cifrada
            byte[] encMsg = encWrappedData[0];
            byte[] encKey = encWrappedData[1];

            // Desenvolvemos la clave con la clave privada
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.UNWRAP_MODE, priv);
            SecretKey sKey = (SecretKey) cipher.unwrap(encKey, "AES", Cipher.SECRET_KEY);

            // Desencriptamos el mensaje con la clave embolcallada
            cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, sKey);
            byte[] decMsg = cipher.doFinal(encMsg);
            return decMsg;
        } catch (Exception ex) {
            System.err.println("Ha succeït un error desxifrant: " + ex);
            return null;
        }
    }







}
