import java.sql.*;
import javax.servlet.http.*;

public class UserServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String username = req.getParameter("username");
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/appdb", "root", "pass");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query);
        while (rs.next()) {
            resp.getWriter().println(rs.getString("email"));
        }
        rs.close();
        stmt.close();
        conn.close();
    }
}