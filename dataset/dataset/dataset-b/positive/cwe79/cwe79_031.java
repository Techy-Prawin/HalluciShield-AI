import javax.servlet.http.*;
import java.io.*;

public class ProfileServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        String username = request.getParameter("username");
        out.println("<html><body>");
        out.println("<h1>Welcome, " + username + "</h1>");
        out.println("</body></html>");
    }
}