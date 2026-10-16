public class FileDownloader {
    public void download(String filename) throws IOException {
        String baseDir = "/var/www/files/";
        String fullPath = baseDir + filename;
        File file = new File(fullPath);
        FileInputStream fis = new FileInputStream(file);
        // ... read file
    }
}