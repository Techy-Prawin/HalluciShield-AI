import java.sql.*;

public class UserDAO {
    public User getUserById(int id) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/appdb", "root", "password");
        String sql = "SELECT * FROM users WHERE id = " + id;
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        if (rs.next()) {
            return new User(rs.getInt("id"), rs.getString("username"));
        }
        return null;
    }
}