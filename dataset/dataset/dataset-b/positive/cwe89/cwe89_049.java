import java.sql.*;

public class UserDAO {
    private Connection connection;

    public UserDAO(Connection connection) {
        this.connection = connection;
    }

    public ResultSet getUserById(String userId) throws SQLException {
        String sql = "SELECT * FROM users WHERE id = '" + userId + "'";
        Statement stmt = connection.createStatement();
        return stmt.executeQuery(sql);
    }
}