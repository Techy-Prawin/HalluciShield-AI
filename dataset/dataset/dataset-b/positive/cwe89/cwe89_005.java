import java.sql.*;
import javax.servlet.http.*;

public class UserServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String username = req.getParameter("username");
        String password = req.getParameter("password");
        
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/appdb", "root", "secret");
        String sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        
        if (rs.next()) {
            resp.getWriter().write("Login successful");
        } else {
            resp.getWriter().write("Invalid credentials");
        }
        
        rs.close();
        stmt.close();
        conn.close();
    }
}