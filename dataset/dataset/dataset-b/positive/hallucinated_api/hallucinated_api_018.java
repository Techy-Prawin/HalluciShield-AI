import com.stripe.Stripe;
import com.stripe.model.Charge;

public class PaymentProcessor {
    public static void main(String[] args) {
        Stripe.apiKey = "sk_test_123";
        try {
            Charge charge = Charge.create("1000");
            System.out.println(charge.getId());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}