package Participants;

import java.net.*;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.concurrent.ThreadLocalRandom;

import RSA.RSAUtil;

import java.io.*;
import java.math.BigInteger;

public class Bob {

	public static void main(String[] args) {
		
		ServerSocket socket;
		boolean fin = false;
		
		try {
			KeyPair bobPair = RSAUtil.produceKeyPair();
			
			RSAPrivateCrtKey bobPrivate = (RSAPrivateCrtKey) bobPair.getPrivate();
			RSAPublicKey bobPublic = (RSAPublicKey) bobPair.getPublic();
			
			socket = new ServerSocket(6000);
			Socket socketCli = socket.accept();
			
			
			sendPublicKey(socketCli, bobPrivate, bobPublic);
			
			DataOutputStream dout = new DataOutputStream(socketCli.getOutputStream());
			DataInputStream din = new DataInputStream(socketCli.getInputStream());
			
			do {
				String msg = din.readUTF();
				System.out.println("--- "+msg);
				if(Boolean.parseBoolean(msg)) {
					System.out.println("Creatig challenge");
					byte[] challenge = new byte[10000];
					String str = "This is the challenge string";
					challenge = str.getBytes();
					//ThreadLocalRandom.current().nextBytes(challenge);
					Signature sig = Signature.getInstance("SHA256withRSA");
					sig.initSign(bobPrivate);
					sig.update(challenge);
					byte[] signature = sig.sign();

					System.out.println("Send challenge");
					dout.writeInt(challenge.length);
					dout.write(challenge);
					dout.writeInt(signature.length);
					dout.write(signature);
				}
			} while(true);
		} catch (Exception e) {
			System.err.println(e.getMessage());
			System.exit(1);
		}
	}

	private static void sendPublicKey(Socket socketCli, RSAPrivateCrtKey bobPrivate, RSAPublicKey bobPublic) 
			throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		PrintWriter cOut = new PrintWriter(socketCli.getOutputStream(), true);
		System.out.println(bobPublic.toString());
		cOut.println(bobPublic.getEncoded().length);
		socketCli.getOutputStream().write(bobPublic.getEncoded());
		socketCli.getOutputStream().flush();
	}
}
