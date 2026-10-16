import java.io.*;

public class FileHandler {
    public static void main(String[] args) throws IOException {
        String userInput = "../../etc/passwd"; // Simulated user input
        File file = new File("/var/data/" + userInput);
        BufferedReader reader = new BufferedReader(new FileReader(file));
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }
        reader.close();
    }
}