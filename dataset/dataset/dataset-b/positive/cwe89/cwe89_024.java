import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

public class UserService {
    public ResultSet getUserById(String userId) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/appdb", "root", "password");
        Statement stmt = conn.createStatement();
        String sql = "SELECT * FROM users WHERE id = '" + userId + "'";
        ResultSet rs = stmt.executeQuery(sql);
        return rs;
    }
}