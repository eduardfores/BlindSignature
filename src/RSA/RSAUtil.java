package RSA;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

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
	
	public static void sendPublicKey(Socket socketCli, RSAPrivateCrtKey bobPrivate, RSAPublicKey bobPublic) 
			throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		PrintWriter cOut = new PrintWriter(socketCli.getOutputStream(), true);
		System.out.println(bobPublic.toString());
		cOut.println(bobPublic.getEncoded().length);
		socketCli.getOutputStream().write(bobPublic.getEncoded());
		socketCli.getOutputStream().flush();
	}
	
	public static RSAPublicKey recivePublicKey(Socket socket, BufferedReader aliceIn) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		int len = Integer.parseInt(aliceIn.readLine());
		byte[] bobPublic = new byte[len];
		socket.getInputStream().read(bobPublic,0,len);
		X509EncodedKeySpec ks = new X509EncodedKeySpec(bobPublic);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		Key publicKey = kf.generatePublic(ks);
		return (RSAPublicKey) publicKey;
	}
	
	public static void verifyChallenge(DataInputStream din, DataOutputStream dout, Signature sig, RSAPublicKey bobPublic) throws IOException, InvalidKeyException, SignatureException {
		int dataLen = din.readInt(); 
		byte challenge[] = new byte[dataLen]; 
		din.read(challenge); 
		int signatureLen = din.readInt(); 
		byte[] signature = new byte[signatureLen]; 
		din.read(signature);
		System.out.println("The challenge is: " + new String(challenge));
		System.out.println("------");
		System.out.println("The signature is " + new String(signature));
		sig.initVerify(bobPublic);
		sig.update(challenge);
		
		boolean keyPairMatches = sig.verify(signature);
		
		System.out.println("The challenge result is: " + keyPairMatches);
	}
}
