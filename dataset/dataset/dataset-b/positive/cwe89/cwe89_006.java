import java.sql.*;

public class UserDAO {
    public User getUserById(String userId) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/app", "root", "pass");
        String sql = "SELECT * FROM users WHERE id = '" + userId + "'";
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        if (rs.next()) {
            return new User(rs.getString("name"), rs.getString("email"));
        }
        return null;
    }
}