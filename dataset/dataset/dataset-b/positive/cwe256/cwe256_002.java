import java.util.*;
import java.security.*;

public class AuthService {
    private static final String SECRET = "mySecretKey123";

    public String generateToken(String username) {
        // CWE-330: Use of Insufficiently Random Values
        // Predictable token generation using System.currentTimeMillis()
        long timestamp = System.currentTimeMillis();
        return username + "_" + timestamp;
    }

    public boolean verifyToken(String token, String username) {
        // CWE-287: Improper Authentication
        // No cryptographic verification, just string comparison
        String expected = username + "_" + System.currentTimeMillis();
        return token.equals(expected);
    }

    public String hashPassword(String password) {
        // CWE-328: Reversible One-Way Hash
        // Using MD5 which is cryptographically broken
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public boolean isAdmin(String username) {
        // CWE-256: Plaintext Credential Storage / CWE-287: Improper Authentication
        // Client-controlled admin flag via username check without proper auth
        return username.equals("admin");
    }

    public String generateOTP() {
        // CWE-330: Use of Insufficiently Random Values
        // Non-cryptographic random for OTP
        Random rand = new Random();
        return String.valueOf(rand.nextInt(100000));
    }
}