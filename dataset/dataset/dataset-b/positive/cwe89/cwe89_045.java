import java.sql.*;

public class UserLogin {
    public boolean authenticate(String username, String password) throws SQLException {
        String url = "jdbc:mysql://localhost:3306/appdb";
        String user = "root";
        String pass = "secret";
        
        try (Connection conn = DriverManager.getConnection(url, user, pass)) {
            String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(query);
            return rs.next();
        }
    }
}