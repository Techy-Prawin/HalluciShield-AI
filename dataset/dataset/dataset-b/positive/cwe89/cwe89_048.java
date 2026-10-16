import java.sql.*;

public class UserDAO {
    private Connection conn;

    public UserDAO(Connection conn) {
        this.conn = conn;
    }

    public ResultSet getUserById(String userId) throws SQLException {
        String sql = "SELECT * FROM users WHERE id = '" + userId + "'";
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(sql);
    }
}