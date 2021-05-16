package Participants;

import java.net.*;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;

import RSA.RSAUtil;

import java.io.*;

public class Alice {

	public static void main(String[] args) {
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
		Socket socket;
		boolean end = false;
		
		try {
			socket = new Socket("localhost", 6000);
			BufferedReader aliceIn = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			
			RSAPublicKey bobPublic = RSAUtil.recivePublicKey(socket, aliceIn);
			System.out.println(bobPublic);
		
			DataOutputStream dout = new DataOutputStream(socket.getOutputStream());
			DataInputStream din = new DataInputStream(socket.getInputStream());
			Signature sig = Signature.getInstance("SHA256withRSA");
			
			do {
				System.out.println("Do you want challenge? True: 1 / False: 0");
				
				boolean petition =Integer.parseInt(in.readLine()) == 1 ? true : false;
				dout.writeUTF( String.valueOf(petition));
				
				if(petition) {
					RSAUtil.verifyChallenge(din, dout, sig, bobPublic);
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

	
}
