import javax.servlet.http.*;
import java.io.*;

public class XSSServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.setContentType("text/html");
        PrintWriter out = resp.getWriter();
        String userInput = req.getParameter("name");
        out.println("<html><body>");
        out.println("<h1>Hello, " + userInput + "</h1>");
        out.println("</body></html>");
    }
}