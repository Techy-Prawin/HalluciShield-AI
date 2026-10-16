import java.sql.*;

public class UserSearch {
    public static void main(String[] args) {
        String username = "admin' OR '1'='1";
        String sql = "SELECT * FROM users WHERE username = '" + username + "'";
        try (Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/app", "root", "pass")) {
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(sql);
            while (rs.next()) {
                System.out.println(rs.getString("username"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}