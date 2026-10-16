import java.security.MessageDigest;
import java.util.UUID;

public class AuthService {
    public boolean login(String username, String password) {
        String storedHash = "5f4dcc3b5aa765d61d8327deb882cf99"; // MD5 hash of 'password'
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return storedHash.equals(sb.toString());
        } catch (Exception e) {
            return false;
        }
    }

    public String generateToken() {
        return UUID.randomUUID().toString();
    }

    public boolean isAdmin(String role) {
        return "admin".equals(role);
    }
}