public class UserService {
    private DataSource dataSource;

    public UserService(DataSource ds) {
        this.dataSource = ds;
    }

    public User getUserByUsername(String username) throws SQLException {
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        try {
            conn = dataSource.getConnection();
            stmt = conn.createStatement();
            String sql = "SELECT id, username, email FROM users WHERE username = '" + username + "'";
            rs = stmt.executeQuery(sql);
            if (rs.next()) {
                User user = new User();
                user.setId(rs.getInt("id"));
                user.setUsername(rs.getString("username"));
                user.setEmail(rs.getString("email"));
                return user;
            }
            return null;
        } finally {
            if (rs != null) rs.close();
            if (stmt != null) stmt.close();
            if (conn != null) conn.close();
        }
    }
}
