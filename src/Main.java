import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

public class Main {
    public static Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) throws Exception {

        Main.decryptRandom();
        Main.addKeyToKeyStore();
        Main.laodKeyStore();
        Main.devolverPublicKeyAPartirDeUnCert();
        Main.devolverPublicKeyAPartirDeUnPrivateKey();
        Main.devolverSignatura();
        Main.comprovarInfo();
        Main.xifrarYDescifrarAmbClauEmbolcallada();

    }



    public static void decryptRandom() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        System.out.println("Ex 1");
        //Generamos un par de claves de 1024 bits
        KeyPair keyPair= UtilitatsXifrar.randomGenerate(1024);
        System.out.println("Escribe el texto a encriptar");
        // Le pedimos al usuario que escriba el texto a encriptar
        String textAEncriptar = scanner.nextLine();

        // Encriptamos el texto con la clave publica del keypair
        byte[] textAEncriptarBytes = UtilitatsXifrar.encryptData(textAEncriptar.getBytes(),keyPair);

        // Y desencriptamos el mensaje con la clave privada del keypair
        byte[] textDesxifratBytes = UtilitatsXifrar.decryptData(textAEncriptarBytes, keyPair);
        String textDesxifrat = new String(textDesxifratBytes);
        //Lo mostramos por pantalla
        System.out.println(textDesxifrat);


    }
    public static void laodKeyStore() throws Exception {
        System.out.println("---------------------------------------");
        System.out.println("Ex 2.1");
        //Cargamos el keystore en memoria
        KeyStore keyStore = UtilitatsXifrar.loadKeyStore("keystore_ruben.ks","ubuntu");
        //Tipus de keystore
        System.out.println("Tipo de keystore: " + keyStore.getType());
        //Cantidad de claves almacenadas
        int numKeys = keyStore.size();
        System.out.println("Mida del magatzem (quantes claus hi ha?): " + numKeys);

        //Los alias de todas las claves almacenadas
        Enumeration<String> aliases = keyStore.aliases();
        System.out.println("Àlies de totes les claus emmagatzemades:");
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            System.out.println(alias);
        }

        // Obtener el certificado de una de las claves por su alias
        String keyAlias = "lamevaclaum9";
        X509Certificate cert = (X509Certificate) keyStore.getCertificate(keyAlias);
        System.out.println("Certificat de la clau " + keyAlias + ": " + cert);

        // Obtener el algoritmo de cifrado de alguna de las claves por su alias
        String keyAlias2 = "lamevaclaum9"; // Reemplaza esto con el alias de la clave que deseas obtener
        Key key = keyStore.getKey(keyAlias2, "ubuntu".toCharArray()); // Reemplaza esto con la contraseña de la clave
        String algorithm = key.getAlgorithm();
        System.out.println("Algorisme de xifrat de la clau " + keyAlias2 + ": " + algorithm);


    }
    public static void addKeyToKeyStore() throws Exception {
        System.out.println("---------------------------------------");
        System.out.println("Ex 2.2");
        //Cargamos el keystore en memoria
        KeyStore keyStore = UtilitatsXifrar.loadKeyStore("keystore_ruben.ks","ubuntu");
        String keyAlias = "ruben"; // Reemplaza esto con el alias que deseas para la clave
        char[] password = "ubuntu".toCharArray(); // Reemplaza esto con la contraseña que deseas para la clave
        SecretKey secretKey = UtilitatsXifrar.keygenKeyGeneration(128); // Reemplaza esto con tu propio método para generar una SecretKey
        //Creamos la nueva entrada
        KeyStore.SecretKeyEntry keyEntry = new KeyStore.SecretKeyEntry(secretKey);
        KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(password);
        keyStore.setEntry(keyAlias, keyEntry, protectionParameter);

        // Guardar el keystore actualizado en un archivo
        try (OutputStream out = new FileOutputStream("keystore_ruben.ks")) {
            keyStore.store(out, password);
        }
    }
    public static void devolverPublicKeyAPartirDeUnCert() throws Exception {
        System.out.println("---------------------------------------");
        System.out.println("Ex 3");
        PublicKey publicKey = UtilitatsXifrar.getPublicKey("micertificado.cer");
        System.out.println(publicKey.toString());

    }
    public static void devolverPublicKeyAPartirDeUnPrivateKey() throws Exception {
        System.out.println("---------------------------------------");
        System.out.println("Ex 4");
        KeyStore keyStore = UtilitatsXifrar.loadKeyStore("keystore_ruben.ks","ubuntu");
        String alias = "lamevaclaum9";
        String pwd = "ubuntu";
        PublicKey publicKey = UtilitatsXifrar.getPublicKey(keyStore,alias,pwd);
        System.out.println(publicKey.toString());

    }

    public static void comprovarInfo() throws Exception {
        System.out.println("---------------------------------------");
        System.out.println("Ex 6");
        String datos = "hola me llamo ruben";
        byte [] datosByte = datos.getBytes();
        KeyStore keyStore = UtilitatsXifrar.loadKeyStore("keystore_ruben.ks","ubuntu");
        String password = "ubuntu";
        Key key = keyStore.getKey("lamevaclaum9", password.toCharArray());
        PrivateKey privateKey = (PrivateKey) key;
        PublicKey publicKey = UtilitatsXifrar.getPublicKey(keyStore, "lamevaclaum9", password);

        byte[] signature = UtilitatsXifrar.generateSignature(datos, privateKey);
        boolean segur = UtilitatsXifrar.verifySignature(datosByte,signature,publicKey);
        if (segur){
            System.out.println("La informacio es valida");
        }
        else {
            System.out.println("La info no es valida");
        }


    }


    public static void devolverSignatura() throws Exception {
        System.out.println("---------------------------------------");
        System.out.println("Ex 5");
        KeyStore keyStore = UtilitatsXifrar.loadKeyStore("keystore_ruben.ks","ubuntu");
        String password = "ubuntu";
        Key key = keyStore.getKey("lamevaclaum9", password.toCharArray());
        PrivateKey privateKey = (PrivateKey) key;
        String data = "datos a firmar";
        byte[] signature = UtilitatsXifrar.generateSignature(data, privateKey);
        System.out.println(Arrays.toString(signature));
    }
    public static void xifrarYDescifrarAmbClauEmbolcallada(){
        try {
            System.out.println("---------------------------------------");
            System.out.println("Ex 2 Parte 2 Clau embocallada");
            // Generamos un par de claves RSA
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();

            // Creamos un mensaje a cifrar
            String mensaje = "Hola soy Ruben Modamio de 2n DAM";

            // Ciframos el mensaje con la clave pública del destinatario
            PublicKey publicKey = keyPair.getPublic();
            byte[][] encWrappedData = UtilitatsXifrar.encryptWrappedData(mensaje.getBytes(), publicKey);

            // Desciframos el mensaje con la clave privada del destinatario
            PrivateKey privateKey = keyPair.getPrivate();
            byte[] decMsg = UtilitatsXifrar.decryptWrappedData(encWrappedData, privateKey);

            // Imprimimos el mensaje original, el mensaje cifrado y el mensaje descifrado para comprovar que funciona correctamente
            System.out.println("Mensaje original: " + mensaje);
            System.out.println("Mensaje cifrado: " + Base64.getEncoder().encodeToString(encWrappedData[0]) + ", " + Base64.getEncoder().encodeToString(encWrappedData[1]));
            System.out.println("Mensaje descifrado: " + new String(decMsg));
        } catch (Exception ex) {
            System.err.println("Ha succeït un error: " + ex);
        }
    }

}