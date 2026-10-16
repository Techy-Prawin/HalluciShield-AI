import java.security.MessageDigest;
import java.util.UUID;

public class AuthService {
    public boolean login(String username, String password) {
        // CWE-256: Plaintext password comparison
        String storedPassword = "admin123";
        return storedPassword.equals(password);
    }

    public String generateToken() {
        // CWE-330: Predictable token using UUID (not cryptographically secure)
        return UUID.randomUUID().toString();
    }

    public boolean verifyOTP(String userOTP, String expectedOTP) {
        // CWE-328: Weak hash (MD5) used for OTP verification
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest1 = md.digest(userOTP.getBytes());
            byte[] digest2 = md.digest(expectedOTP.getBytes());
            return java.util.Arrays.equals(digest1, digest2);
        } catch (Exception e) {
            return false;
        }
    }

    public boolean isAdmin(String role) {
        // CWE-287: Client-controlled admin flag (no server-side validation)
        return "admin".equals(role);
    }
}