package nl.mansoft.security;

import java.security.Provider;

public class SimProvider extends Provider {
    public SimProvider() {
        super("SimProvider", 1.0, "SIM provider");
        put("SecureRandom.SIM-PRNG", "nl.mansoft.security.SimSecureRandom");
        put("KeyStore.SIM", "nl.mansoft.security.SimKeystore");
        //put("Signature.SHA256withRSA", "smartcardio.SimSignature");
        //put("Signature.SHA256withRSA SupportedKeyClasses", "smartcardio.SimPrivateKey");
        //SimService s = new SimService(this, "SIM", "RSA", SimService.class.getName(), null, null);
        //putService(s);
    }


}
