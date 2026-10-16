import javax.servlet.http.*;
import java.io.*;

public class XSSServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        String userInput = request.getParameter("name");
        out.println("<html><body><h1>Hello, " + userInput + "</h1></body></html>");
    }
}