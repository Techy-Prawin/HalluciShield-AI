public void updateUserEmail(String userId, String newEmail) {
    Connection conn = null;
    Statement stmt = null;
    try {
        conn = dataSource.getConnection();
        stmt = conn.createStatement();
        String sql = "UPDATE users SET email = '" + newEmail + "' WHERE id = '" + userId + "'";
        stmt.executeUpdate(sql);
    } catch (SQLException e) {
        e.printStackTrace();
    } finally {
        if (stmt != null) try { stmt.close(); } catch (SQLException e) {}
        if (conn != null) try { conn.close(); } catch (SQLException e) {}
    }
}
