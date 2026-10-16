import java.io.*;
import javax.servlet.http.*;

public class FileServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String filename = request.getParameter("file");
        File file = new File("/var/data/" + filename);
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                response.getWriter().println(line);
            }
        }
    }
}