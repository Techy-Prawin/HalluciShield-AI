public class ApiClient {
    private static final String API_KEY = "12345-ABCDE-67890-FGHIJ";
    private static final String DB_PASSWORD = "P@ssw0rd!";

    public void connect() {
        // Connect to database using the hardcoded password
        String url = "jdbc:mysql://localhost:3306/mydb";
        java.sql.Connection conn = java.sql.DriverManager.getConnection(url, "user", DB_PASSWORD);
        // ...
    }
}
