package Participants;

import java.net.*;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;

import RSA.RSAUtil;

import java.io.*;
import java.math.BigInteger;

public class Bob {

	public static void main(String[] args) {
		
		ServerSocket socket;
		
		try {
			socket = new ServerSocket(6000);
			System.out.println("Waiting for a Alice ...");
			Socket socketCli = socket.accept();
			System.out.println("Alice accepted");
			DataOutputStream dout = new DataOutputStream(socketCli.getOutputStream());
			DataInputStream din = new DataInputStream(socketCli.getInputStream());
			
			KeyPair bobPair = RSAUtil.produceKeyPair();
			
			RSAPrivateCrtKey bobPrivate = (RSAPrivateCrtKey) bobPair.getPrivate();
			RSAPublicKey bobPublic = (RSAPublicKey) bobPair.getPublic();
			
			sendPublicKey(dout, bobPublic);
			
			
			do {
				String msg = din.readUTF();
				System.out.println("--- "+msg);
				if(Boolean.parseBoolean(msg)) {
					
					BigInteger challenge = reciveChallenge(din);
					System.out.println("Ofuscated message: " + challenge);
					
					BigInteger signature = RSAUtil.sign(challenge, bobPrivate);
					System.out.println("Signature: " + signature);
					
					sendSignature(dout, signature);
				}
			} while(true);
		} catch (Exception e) {
			System.err.println(e.getMessage());
			System.exit(1);
		}
	}

	public static void sendPublicKey(DataOutputStream dout, RSAPublicKey bobPublic) 
			throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		dout.writeInt(bobPublic.getEncoded().length);
		dout.write(bobPublic.getEncoded());
		System.out.println(bobPublic);
	}

	public static BigInteger reciveChallenge(DataInputStream din) throws IOException {
		int len = din.readInt();
		byte[] challenge = new byte[len];
		din.read(challenge);
		return new BigInteger(challenge);
	}
	
	public static void sendSignature(DataOutputStream dout, BigInteger signature) 
			throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		byte[] signatureArray = new byte[10000];
		signatureArray = signature.toByteArray();
		dout.writeInt(signatureArray.length);
		dout.write(signatureArray);
	}
}
