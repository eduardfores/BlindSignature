package Participants;

import java.net.*;
import java.security.KeyPair;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;

import RSA.RSAUtil;

import java.io.*;

public class Bob {

	public static void main(String[] args) {
		
		ServerSocket socket;
		
		try {
			KeyPair bobPair = RSAUtil.produceKeyPair();
			
			RSAPrivateCrtKey bobPrivate = (RSAPrivateCrtKey) bobPair.getPrivate();
			RSAPublicKey bobPublic = (RSAPublicKey) bobPair.getPublic();
			
			socket = new ServerSocket(6000);
			Socket socketCli = socket.accept();
			
			
			RSAUtil.sendPublicKey(socketCli, bobPrivate, bobPublic);
			
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


}
