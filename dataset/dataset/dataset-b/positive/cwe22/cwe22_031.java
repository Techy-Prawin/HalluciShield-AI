import java.io.*;
import javax.servlet.http.*;

public class FileServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String fileName = request.getParameter("file");
        File file = new File("/var/data/" + fileName);
        try (FileInputStream fis = new FileInputStream(file)) {
            response.setContentType("application/octet-stream");
            response.getOutputStream().write(fis.readAllBytes());
        }
    }
}