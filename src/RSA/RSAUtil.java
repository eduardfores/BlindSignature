package RSA;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;

public class RSAUtil {

	public static KeyPair produceKeyPair() {
		try {
			
			KeyPairGenerator rsaKeyPairGenerator = KeyPairGenerator.getInstance("RSA");
			RSAKeyGenParameterSpec spec = new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(3));
			rsaKeyPairGenerator.initialize(spec);
			return rsaKeyPairGenerator.generateKeyPair();
			
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
}
