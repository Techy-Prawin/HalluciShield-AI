import java.sql.*;
import javax.servlet.http.*;
import java.io.*;

public class UserServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        try (Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/appdb", "root", "secret")) {
            String sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(sql);
            
            if (rs.next()) {
                response.getWriter().write("Login successful");
            } else {
                response.getWriter().write("Invalid credentials");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}