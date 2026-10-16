import java.io.*;
import javax.servlet.http.*;

public class FileServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String filename = request.getParameter("file");
        File file = new File("/var/data/" + filename);
        try (FileInputStream fis = new FileInputStream(file)) {
            response.setContentType("application/octet-stream");
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                response.getOutputStream().write(buffer, 0, bytesRead);
            }
        }
    }
}