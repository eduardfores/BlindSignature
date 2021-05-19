package RSA;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;

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
	
	public static void verifyChallenge(DataInputStream din, DataOutputStream dout, Signature sig, RSAPublicKey e) throws IOException, InvalidKeyException, SignatureException {
		int dataLen = din.readInt(); 
		byte challenge[] = new byte[dataLen]; 
		din.read(challenge); 
		int signatureLen = din.readInt(); 
		byte[] signature = new byte[signatureLen]; 
		din.read(signature);
		System.out.println("The challenge is: " + new String(challenge));
		System.out.println("------");
		System.out.println("The signature is " + new String(signature));
		sig.initVerify(e);
		sig.update(challenge);
		
		boolean keyPairMatches = sig.verify(signature);
		
		System.out.println("The challenge result is: " + keyPairMatches);
	}
	
	public static BigInteger ofuscateChallenge(String challenge, RSAPublicKey rsaPublicKey) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchProviderException {
		
		BigInteger r;
		
		byte[] msg = challenge.getBytes("UTF8"); 
		BigInteger m = new BigInteger(msg);  
        BigInteger e = rsaPublicKey.getPublicExponent();
        BigInteger N = rsaPublicKey.getModulus();
        
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");

        byte[] randomBytes = new byte[10]; 
        BigInteger one = new BigInteger("1"); 
        BigInteger gcd = null; 

        do
        {
            random.nextBytes(randomBytes); 
            r = new BigInteger(randomBytes); 
            gcd = r.gcd(N); //calculate the gcd for random number r and the  modulus of the keypair

        }
        while (!gcd.equals(one) || r.compareTo(N) >= 0 || r.compareTo(one) <= 0);
        
        
        return ((r.modPow(e, N)).multiply(m)).mod(N); //H(msg) * r^e mod N
	}
}
