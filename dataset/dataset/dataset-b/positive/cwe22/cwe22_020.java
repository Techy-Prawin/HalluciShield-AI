import java.io.*;

public class FileHandler {
    public String readFile(String filename) throws IOException {
        // CWE-22: Path Traversal
        File file = new File(filename);
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