import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Scanner;
import java.util.zip.CRC32;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class FileTransfer {

	public static void main(String[] args) {
		System.out.println(args[0]);
		if(args[0].equals("makekeys")) {
			makekeys();
		} 
		else if(args[0].equals("server")) {
			try {
				server(args);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		else if(args[0].equals("client")) {
			try {
				client(args);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

	}

	
	public static void makekeys() {
		try {
				KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
				gen.initialize(4096); // you can use 2048 for faster key generation
				KeyPair keyPair = gen.genKeyPair();
				PrivateKey privateKey = keyPair.getPrivate();
				PublicKey publicKey = keyPair.getPublic();
				try (ObjectOutputStream oos = new ObjectOutputStream(
				new FileOutputStream(new File("public.bin")))) {
				oos.writeObject(publicKey);
			}
			try (ObjectOutputStream oos = new ObjectOutputStream(
					new FileOutputStream(new File("private.bin")))) {
				oos.writeObject(privateKey);
			}
		} catch (NoSuchAlgorithmException | IOException e) {
			((Throwable) e).printStackTrace(System.err);
		}
	}
	
	public static void server(String[] args) throws Exception {
		try (ServerSocket serverSocket = new ServerSocket(Integer.parseInt(args[2]))) {
            while (true) {
					Socket socket = serverSocket.accept();
					
					String address = socket.getInetAddress().getHostAddress();
					System.out.printf("Client connected: %s%n", address);
							
					InputStream is = socket.getInputStream();
					OutputStream os = socket.getOutputStream();
					ObjectOutputStream oos = new ObjectOutputStream(os);
					ObjectInputStream ois = new ObjectInputStream(is);
					boolean connection = true;
					int i = 0;
					//Key key = null;
					int chunkSize = 0;
					SecretKeySpec spec = null;
					SecretKey secKey = null;
					String outputFolder = "serverOutput.txt";
					ObjectOutputStream outputFileStream = new ObjectOutputStream(
							new FileOutputStream(new File(outputFolder)));
					while(connection) {
						Message message = (Message)ois.readObject();
						if(MessageType.DISCONNECT == message.getType()) {
							socket.close();
							socket = serverSocket.accept();
							
							address = socket.getInetAddress().getHostAddress();
							System.out.printf("Client connected: %s%n", address);
									
							is = socket.getInputStream();
							os = socket.getOutputStream();
							oos = new ObjectOutputStream(os);
							ois = new ObjectInputStream(is);
						}
						else if(MessageType.START == message.getType()) {
							try{
								StartMessage startMsg = (StartMessage)message;
								ObjectInputStream Fileois = new ObjectInputStream(
										new FileInputStream(new File(args[1])));
								PrivateKey privateKey = (PrivateKey)Fileois.readObject();
								Fileois.close();
								Cipher cipher = Cipher.getInstance("RSA");
								chunkSize = startMsg.getChunkSize();
								cipher.init(Cipher.UNWRAP_MODE, privateKey);
								secKey = (SecretKey)cipher.unwrap(startMsg.getEncryptedKey(), "RSA", cipher.SECRET_KEY);
								spec = new SecretKeySpec(secKey.getEncoded(), "AES");
								oos.writeObject(new AckMessage(0));
							} catch(Exception e) {
								oos.writeObject(new AckMessage(-1));
							}
						}
						else if(MessageType.STOP == message.getType()) {
							i = 0;
							connection = false;
							socket.close();
						}
						else if(MessageType.CHUNK == message.getType()) {
							Chunk chunk = (Chunk)message;
							if(i != chunk.getSeq()) {
								oos.writeObject(new AckMessage(i));
								break;
							} else {
								Cipher dec = Cipher.getInstance("AES");
								dec.init(Cipher.DECRYPT_MODE, spec);
								byte[] originalMsg = dec.doFinal(chunk.getData());
								CRC32 check = new CRC32();
								check.reset();
								check.update(originalMsg);
								if((int)check.getValue() == chunk.getCrc()) {
									outputFileStream.writeObject(originalMsg);
									i++;
									System.out.println("Chunk received: [" + (i) + "\\" + chunkSize + "].");
									oos.writeObject(new AckMessage(i));
								}
							}
						}
					}	
			}
        }
	}
	
	
	public static void client(String[] args) throws Exception {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		SecretKey key = keyGen.generateKey();
		Cipher cipher = Cipher.getInstance("RSA");
		ObjectInputStream Fileois = new ObjectInputStream(
				new FileInputStream(new File(args[1])));
		Key privateKey = (Key)Fileois.readObject();
		cipher.init(Cipher.WRAP_MODE, privateKey);
		byte[] encryptKey = cipher.wrap(key);
		Scanner kb = new Scanner(System.in);
		System.out.print("Enter file to transfer: ");
		String filename = kb.nextLine();
		ObjectInputStream fileStream = null;
		File file = new File(filename);
		while(!file.exists()) {
			System.out.println("This file does not exist, Please Enter another file: ");
			kb.nextLine();
		}
		System.out.print("Enter desired chunk size: ");
		int chunkSize = kb.nextInt();
		try (Socket socket = new Socket("localhost", Integer.parseInt(args[2]))) {
			System.out.println("\nConnected to server.");
			OutputStream os = socket.getOutputStream();
			InputStream is = socket.getInputStream();
			ObjectOutputStream oos = new ObjectOutputStream(os);
			ObjectInputStream ois = new ObjectInputStream(is);
			System.out.println("HI");
			oos.writeObject(new StartMessage(filename, encryptKey, chunkSize));
			System.out.println("HI");
			AckMessage message = (AckMessage)ois.readObject();
			System.out.println("HI");
			if(message.getSeq() == -1) {
				System.out.println("AckMessage returned -1");
				return;
			} else {
				byte[] originalMsg = new byte[(int)file.length()];
				FileInputStream fis = new FileInputStream(file);
				fis.read(originalMsg);
				fis.close();
				int seqTracker = (int) Math.ceil(originalMsg.length/chunkSize);
				System.out.println("Sending +" + seqTracker + " chunks.");
				for(int i = 0; i < seqTracker; i++) {
					byte[] chunkMsg = Arrays.copyOfRange(originalMsg, i*chunkSize, (i+1)*chunkSize-1);
					CRC32 check = new CRC32();
					check.reset();
					check.update(chunkMsg);
					Cipher encrypt = Cipher.getInstance("AES");
					encrypt.init(Cipher.ENCRYPT_MODE, key);
					byte[] encryptedChunkMsg = encrypt.doFinal(chunkMsg);
					oos.writeObject(new Chunk(i, encryptedChunkMsg, (int)check.getValue()));
					System.out.println("Chunks Completed [" + (i+1) + "//" + seqTracker + "]." );
					message = (AckMessage)ois.readObject();
					if(message.getSeq() == i) {
						oos.writeObject(new Chunk(i, encryptedChunkMsg, (int)check.getValue()));
					}
				}
				oos.writeObject(new StopMessage(filename));
				System.out.println("Transfer Complete!");
			}
			socket.close();
		}
	}
}
