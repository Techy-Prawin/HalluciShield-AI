import javax.servlet.http.*;
import java.io.*;

public class XSSVulnerableServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("name");
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println("<h1>Hello, " + userInput + "</h1>");
        out.println("<script>document.write('Welcome, " + userInput + "');</script>");
        out.println("</body></html>");
    }
}