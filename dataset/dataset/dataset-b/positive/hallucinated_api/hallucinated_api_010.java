import com.stripe.Stripe;
import com.stripe.model.Charge;

public class PaymentProcessor {
    public static void main(String[] args) {
        Stripe.apiKey = "sk_test_123";
        Charge charge = Charge.create("cus_123", 1000, "USD");
        System.out.println(charge.getId());
    }
}