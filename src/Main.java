import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Scanner;

public class Main {
    public static Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) throws NoSuchPaddingException, IllegalBlockSizeException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        Main.xifrarYDesxifrarAmbClauAleatoria();
        Main.xifrarYDesxifrarAmbClauGeneradaAPartirDeUnaParaula("pas");
        Main.xifrarYDesxifrarAmbClauGeneradaAPartirDeUnaParaulaBadPadding();
        Main.trobarContrasena();

    }

    public static void xifrarYDesxifrarAmbClauAleatoria(){
        try {

            System.out.println("EX1.5--------------------------------------------------------");
            // Generem una clau aleatòria de 256 bits
            SecretKey key = UtilitatsXifrar.keygenKeyGeneration(256);
            System.out.println("Escribe el texto a encriptar");
            // Text en clar que volem xifrar
            String textAEncriptar = scanner.nextLine();

            // Convertim el text en clar a un array de bytes
            byte[] textAEncriptarBytes = textAEncriptar.getBytes();

            // Xifrem el text amb la clau generada
            byte[] textXifratBytes = UtilitatsXifrar.encryptData(textAEncriptarBytes, key);

            // Desxifrem el text xifrat amb la mateixa clau
            byte[] textDesxifratBytes = UtilitatsXifrar.decryptData(textXifratBytes, key);

            // Convertim el text desxifrat a una cadena de caràcters
            String textDesxifrat = new String(textDesxifratBytes);

            // Mostrem el text original, el text xifrat i el text desxifrat per pantalla
            System.out.println("Text original: " + textAEncriptar);
            System.out.println("Text xifrat: " + Arrays.toString(textXifratBytes));
            System.out.println("Text desxifrat: " + textDesxifrat);

        } catch (Exception e) {
            System.err.println(e);
        }
    }
    public static void xifrarYDesxifrarAmbClauGeneradaAPartirDeUnaParaula(String paraula){
        try {
            System.out.println("EX1.6--------------------------------------------------------");
            // Generem una clau a partir d'una paraula de pas de 128 bits
            SecretKey key = UtilitatsXifrar.passwordKeyGeneration(paraula, 128);
            System.out.println("Escribe el texto a encriptar");
            // Text en clar que volem xifrar
            String textAEncriptar = scanner.nextLine();

            // Convertim el text en clar a un array de bytes
            byte[] textAEncriptarBytes = textAEncriptar.getBytes();

            // Xifrem el text amb la clau generada a partir de la paraula de pas
            byte[] textXifratBytes = UtilitatsXifrar.encryptData(textAEncriptarBytes, key);

            // Desxifrem el text xifrat amb la mateixa clau generada a partir de la paraula de pas
            byte[] textDesxifratBytes = UtilitatsXifrar.decryptData(textXifratBytes, key);

            // Convertim el text desxifrat a una cadena de caràcters
            String textDesxifrat = new String(textDesxifratBytes);

            // Mostrem el text original, el text xifrat i el text desxifrat per pantalla
            System.out.println("Text original: " + textAEncriptar);
            System.out.println("Text xifrat: " + Arrays.toString(textXifratBytes));
            System.out.println("Text desxifrat: " + textDesxifrat);

            System.out.println("EX1.7--------------------------------------------------------");
            System.out.println("Algoritmo" + key.getAlgorithm());
            System.out.println("Codificacion" + key.getEncoded());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public static void xifrarYDesxifrarAmbClauGeneradaAPartirDeUnaParaulaBadPadding(){
        try {
            System.out.println("EX1.8--------------------------------------------------------");
            // Generem una clau a partir d'una paraula de pas de 128 bits
            String paraulaDePas = "pasIncorrecto";
            SecretKey key = UtilitatsXifrar.passwordKeyGeneration(paraulaDePas, 128);

            // Text xifrat que volem desxifrar
            byte[] textXifratBytes = {67, -19, 116, -55, 17, 89, 52, 31, -81, -65, 40, 73, 69, -41, 67, -73};

            // Desxifrem el text xifrat amb una clau generada a partir d'una paraula de pas incorrecta
            byte[] textDesxifratBytes = UtilitatsXifrar.decryptData(textXifratBytes, key);

            // Convertim el text desxifrat a una cadena de caràcters
            if (textDesxifratBytes != null){
                String textDesxifrat = new String(textDesxifratBytes);

                // Mostrem el text desxifrat per pantalla
                System.out.println("Text desxifrat: " + textDesxifrat);
            }


        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void trobarContrasena() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
            // Llegim el contingut del fitxer "clausA4.txt" per obtenir una llista de possibles contrasenyes
            System.out.println("EX2--------------------------------------------------------");
            BufferedReader reader = new BufferedReader(new FileReader("clausA4.txt"));
            String line = reader.readLine();
            Path path = Paths.get("textamagat.crypt");
//            FileInputStream fis = new FileInputStream("textamagat.crypt");
            byte[] contingutEncriptat = Files.readAllBytes(path);
//            fis.close();
            while (line != null) {
                SecretKey key = UtilitatsXifrar.passwordKeyGeneration(line, 128);
                byte[] contingutDesxifrat = UtilitatsXifrar.decryptData(contingutEncriptat, key);
                if (contingutDesxifrat != null) {
                    String textDescifrat = new String(contingutDesxifrat, "UTF8");
                    System.out.println("Fitxer descifrat");
                    System.out.println(line);
                    System.out.println(textDescifrat);
                    break;

                }
                line = reader.readLine();
            }
            reader.close();


    }
}