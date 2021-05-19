package Participants;

import java.net.*;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
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
			
			RSAPublicKey e = recivePublicKey(din);
			System.out.println(e);
		
			
			Signature sig = Signature.getInstance("SHA256withRSA");
			
			do {
				System.out.println("Do you want challenge? True: 1 / False: 0");
				
				boolean petition = Integer.parseInt(in.readLine()) == 1 ? true : false;
				dout.writeUTF( String.valueOf(petition));
				
				if(petition) {

					String msg = "This is the challenge";
					System.out.println("Message: " + msg);
					BigInteger challenge = RSAUtil.ofuscateChallenge(msg, e);
					System.out.println("Message ofiscated: "+challenge);
					sendChallengeToBob(dout, challenge);
					
					//RSAUtil.verifyChallenge(din, dout, sig, e);
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
		byte[] challenge = new byte[10000];
		challenge = message.toByteArray();
		dout.write(challenge);
	}
	
}
