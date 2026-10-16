import javax.servlet.http.*;
import java.io.*;

public class XSSServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("name");
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println("<h1>Hello, " + userInput + "!</h1>");
        out.println("</body></html>");
    }
}
