import java.io.*;

public class FileHandler {
    public String readFile(String userInput) throws IOException {
        File file = new File("/data/" + userInput);
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