import java.sql.*;

public class UserService {
    private Connection connection;

    public UserService(Connection connection) {
        this.connection = connection;
    }

    public ResultSet getUserById(String userId) throws SQLException {
        String sql = "SELECT * FROM users WHERE id = '" + userId + "'";
        Statement stmt = connection.createStatement();
        return stmt.executeQuery(sql);
    }
}