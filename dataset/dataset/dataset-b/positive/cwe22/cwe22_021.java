import java.io.*;

public class FileHandler {
    public String readFile(String filename) throws IOException {
        // Vulnerable: filename is directly used without sanitization
        File file = new File("/var/data/" + filename);
        BufferedReader reader = new BufferedReader(new FileReader(file));
        StringBuilder content = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            content.append(line).append("\n");
        }
        reader.close();
        return content.toString();
    }
}