package Participants;

import java.net.*;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import RSA.RSAUtil;

import java.io.*;

public class Alice {

	public static void main(String[] args) {
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
		Socket socket;
		boolean end = false;
		byte[] mensajeBytes = new byte[256];
		
		String msg = "";
		
		try {
			socket = new Socket("localhost", 6000);
			BufferedReader aliceIn = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			
			RSAPublicKey bobPublic = recivePublicKey(socket, aliceIn);
			System.out.println(bobPublic);
		
			DataOutputStream dout = new DataOutputStream(socket.getOutputStream());
			DataInputStream din = new DataInputStream(socket.getInputStream());
			Signature sig = Signature.getInstance("SHA256withRSA");
			
			do {
				System.out.println("Do you want challenge? True: 1 / False: 0");
				
				boolean petition =Integer.parseInt(in.readLine()) == 1 ? true : false;
				dout.writeUTF( String.valueOf(petition));
				
				if(petition) {
					verifyChallenge(din, dout, sig, bobPublic);
				} else {
					System.out.println("Alice does not want any challenge");
					end = true;
				}
				
			} while(!end);
			
		} catch (Exception e) {
			System.err.println(e.getMessage());
			System.exit(1);
		}

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
		System.out.println("The challenge is: " + new String(signature));
		
		sig.initVerify(bobPublic);
		sig.update(challenge);
		
		boolean keyPairMatches = sig.verify(signature);
		
		System.out.println("The challenge result is: " + keyPairMatches);
	}
}
