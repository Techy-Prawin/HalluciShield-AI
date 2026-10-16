import java.io.*;

public class FileHandler {
    public void readFile(String userInput) throws IOException {
        File file = new File(userInput);
        BufferedReader reader = new BufferedReader(new FileReader(file));
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }
        reader.close();
    }
}