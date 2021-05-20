package Participants;

import java.net.*;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import RSA.RSAUtil;

import java.io.*;
import java.math.BigInteger;

public class Alice {

	public static void main(String[] args) {
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
		Socket socket;
		boolean end = false;
		
		try {
			socket = new Socket("localhost", 6000);
			DataOutputStream dout = new DataOutputStream(socket.getOutputStream());
			DataInputStream din = new DataInputStream(socket.getInputStream());
			
			RSAPublicKey bobPublicKey = recivePublicKey(din);
			System.out.println(bobPublicKey);
			
			do {
				System.out.println("Do you want challenge? True: 1 / False: 0");
				
				boolean petition = Integer.parseInt(in.readLine()) == 1 ? true : false;
				dout.writeUTF( String.valueOf(petition));
				
				if(petition) {

					String msg = "This is the challenge";
					System.out.println("Message: " + msg);
					
					BigInteger blindingFactor = RSAUtil.generateBlindingFactor(bobPublicKey);
					BigInteger challenge = RSAUtil.ofuscateChallenge(msg, bobPublicKey, blindingFactor);
					
					sendChallengeToBob(dout, challenge);
					
					BigInteger signature = reciveSignature(din);
					BigInteger s = RSAUtil.extractSignature(signature, bobPublicKey, blindingFactor);
					
					System.out.println("BlindingFactor: " + blindingFactor);
					System.out.println("Message ofiscated: " + challenge);
					System.out.println("Blind Signature: " + signature);
			        System.out.println("S: " + s);
			        
			        boolean checkSignature = RSAUtil.verifyWithEulersTheorem(s, bobPublicKey, msg);
			        
			        if(checkSignature) {
			        	System.out.println("\nThe signature is correct");
			        }else {

			        	System.out.println("The signature is not correct");
			        }
				} else {
					System.out.println("Alice does not want any challenge");
					end = true;
				}
				
			} while(!end);
			
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}

	}

	public static RSAPublicKey recivePublicKey(DataInputStream din) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		int len = din.readInt();
		byte[] bobPublic = new byte[len];
		din.read(bobPublic);
		X509EncodedKeySpec ks = new X509EncodedKeySpec(bobPublic);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		Key publicKey = kf.generatePublic(ks);
		return (RSAPublicKey) publicKey;
	}
	
	public static void sendChallengeToBob(DataOutputStream dout, BigInteger message) throws IOException {
		System.out.println("Sending information to Bob....");
		byte[] challenge = new byte[10000];
		challenge = message.toByteArray();
		dout.writeInt(challenge.length);
		dout.write(challenge);
		System.out.println("Information sent");
	}
	
	public static BigInteger reciveSignature(DataInputStream din) throws IOException {
		int len = din.readInt();
		byte[] signature = new byte[len];
		din.read(signature);
		return new BigInteger(signature);
	}
	
}
