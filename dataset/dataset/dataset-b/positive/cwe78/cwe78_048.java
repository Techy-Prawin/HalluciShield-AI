import java.io.*;

public class Vulnerable {
    public static void main(String[] args) throws IOException {
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        System.out.print("Enter file name: ");
        String fileName = br.readLine();
        // Vulnerable: executes user-supplied file name
        Runtime.getRuntime().exec("ls " + fileName);
    }
}