import java.security.MessageDigest;
import java.util.UUID;

public class AuthService {
    public boolean login(String username, String password) {
        // CWE-256: Plaintext password comparison
        String storedPassword = "admin123";
        return storedPassword.equals(password);
    }

    public String generateToken() {
        // CWE-330: Predictable token using System.currentTimeMillis
        return "token_" + System.currentTimeMillis();
    }

    public boolean verifyOTP(String userOTP, String serverOTP) {
        // CWE-328: Non-crypto OTP comparison (timing attack vulnerable)
        return userOTP.equals(serverOTP);
    }

    public boolean isAdmin(String role) {
        // CWE-287: Client-controlled admin role
        return "admin".equals(role);
    }
}