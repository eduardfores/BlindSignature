package RSA;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
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
	
	public static BigInteger generateBlindingFactor(RSAPublicKey rsaPublicKey) throws NoSuchAlgorithmException, NoSuchProviderException {
		BigInteger r;
		
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
        
		return r;
	}
	public static BigInteger ofuscateChallenge(String challenge, RSAPublicKey rsaPublicKey, BigInteger r) throws UnsupportedEncodingException {
		
		byte[] msg = challenge.getBytes("UTF8"); 
		BigInteger m = new BigInteger(msg);  
        BigInteger e = rsaPublicKey.getPublicExponent();
        BigInteger N = rsaPublicKey.getModulus();
        
        return (m.multiply(r.modPow(e, N))).mod(N); // m * r^e mod N
	}
	
	public static BigInteger sign(BigInteger mprime, RSAPrivateKey rsaPrivateKey) {
		
		BigInteger N = rsaPrivateKey.getModulus(); 
		BigInteger d = rsaPrivateKey.getPrivateExponent();
        BigInteger s = (mprime.modPow(d, N)).mod(N); // m'^d mod N
        return s;
	}
	
	public static BigInteger extractSignature(BigInteger sprime, RSAPublicKey rsaPublicKey, BigInteger r) {
		
        BigInteger N = rsaPublicKey.getModulus();
        BigInteger s = (sprime.multiply(r.modPow(BigInteger.ONE.negate(), N))).mod(N); // s' * r^-1 mod N
        
        return s;
	}
	
	public static boolean verifyWithEulersTheorem(BigInteger s, RSAPublicKey rsaPublicKey, String m) throws UnsupportedEncodingException {
		
        BigInteger N = rsaPublicKey.getModulus();
        BigInteger e = rsaPublicKey.getPublicExponent();
        
        BigInteger messageFromS = (s.modPow(e, N)).mod(N); // S^e mod N
        byte[] msg = m.getBytes("UTF8"); 
		BigInteger mInteger = new BigInteger(msg);
        
        return mInteger.compareTo(messageFromS) == 0; // if are equals will return 0 and 0 == 0 is true
	}

}
