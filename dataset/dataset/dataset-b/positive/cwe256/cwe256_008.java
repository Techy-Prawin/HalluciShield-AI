import java.security.MessageDigest;
import java.util.Random;

public class AuthService {
    public static String hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(password.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static String generateToken() {
        Random r = new Random();
        return String.valueOf(r.nextInt(100000));
    }

    public static boolean isAdmin(String role) {
        return role.equals("admin");
    }

    public static void main(String[] args) throws Exception {
        String userPwd = "password123";
        String hashed = hashPassword(userPwd);
        String token = generateToken();
        boolean admin = isAdmin("admin");
        System.out.println("Hash: " + hashed);
        System.out.println("Token: " + token);
        System.out.println("Admin: " + admin);
    }
}