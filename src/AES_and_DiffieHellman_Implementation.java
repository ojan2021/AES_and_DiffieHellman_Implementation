import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class AES_and_DiffieHellman_Implementation {
	static int a;
	static int b;
	static int p;
	static int g;
	static byte[] iv = new byte[16];
	static byte[] decIv = new byte[16];
	static ArrayList<byte[]> blocks = new ArrayList<byte[]>();
	static int padCount = 0;

	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

		Scanner sc = new Scanner(System.in);
		int alicePubKey;
		int aliceEncKey;
		int bobPubKey;
		int bobEncKey;
		String plainText;
		int inputEncKey;

		// Getting Prime and Generators
		System.out.print("Plese enter your prime: ");
		p = sc.nextInt();
		System.out.print("Plese enter your generator: ");
		g = sc.nextInt();

		// Getting Public Keys
		alicePubKey = pubKeyAlice();
		bobPubKey = pubKeyBob();

		// Getting Common Encryption Keys for Alice and Bob
		System.out.println();
		aliceEncKey = encryptedKey(bobPubKey, a, p);
		bobEncKey = encryptedKey(alicePubKey, b, p);

		System.out.println("Public Key of Alice is: " + alicePubKey);
		System.out.println("Private Key of Alice is: " + a);
		System.out.println("Public Key of Bob is: " + bobPubKey);
		System.out.println("Private Key of Bob is: " + b);
		System.out.println("Our common secure keys are: " + aliceEncKey + " and " + bobEncKey);

		// We get our plain text from user.
		sc.nextLine();
		System.out.print("Please enter your plain text: ");
		plainText = sc.nextLine();
		System.out.print("Please enter your encryption key: ");
		inputEncKey = sc.nextInt();

		// Generating IV.
		SecureRandom random = new SecureRandom();
		random.nextBytes(iv);
		decIv = iv;
		System.out.println("Our Initial Vector is: " + bytesToHex(iv));
		
		//Encryption process.
		String encryptedText = bytesToHex(encryptedText(inputEncKey, plainText));
		System.out.println("Here's your encrypted text: " + encryptedText);

		// Decrypting cipher text.
		String decryptedText = new String(decryptedText(inputEncKey, encryptedText(inputEncKey, plainText)),
				Charset.forName("UTF-8"));
		if (padCount != decryptedText.length())
			decryptedText = decryptedText.substring(0, padCount);
		System.out.println("Here's your decrypted text: " + decryptedText);

		sc.close();
	}

	/** We are calculating Public Key for Alice in this function **/
	public static int pubKeyAlice() {
		a = 4;
		int pubKey = (int) Math.pow(g, a) % p;
		return pubKey;
	}

	/** We are calculating Public Key for Bob in this function **/
	public static int pubKeyBob() {
		b = 3;
		int pubKey = (int) (Math.pow(g, b) % p);
		return pubKey;
	}

	/**
	 * We are calculating Common Encryption Key for Alice and Bob in this function
	 **/
	public static int encryptedKey(int pubKey, int privKey, int p) {
		int encKey = (int) (Math.pow(pubKey, privKey) % p);
		return encKey;
	}

	/** We are doing AES ecnryption with Cipher Block Chaining Mode in there **/
	public static byte[] encryptedText(int encKey, String plainText)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, InvalidAlgorithmParameterException {

		// We are creating encryption key for AES in there
		String keyFile = encKey + "000000000000000";
		if(keyFile.length()>16)
			keyFile=keyFile.substring(0,16);
		byte[] keyb = new byte[16];
		keyb = keyFile.getBytes();
		SecretKeySpec skey = new SecretKeySpec(keyb, "AES");

		// Padding for plain text in order to complete 16 bytes for AES algorithm.
		padCount = plainText.length();
		for (int i = 0; i < 16; i++) {
			if (plainText.length() % 16 != 0) {
				plainText = plainText + plainText.charAt(i % 16);
			}
		}

		/**
		 * In there, we are dividing our plain text into blocks and doing XOR operation
		 * between Initial Vector and Plain Text block. After XORing, we are encrypting
		 * this block and replacing this encrypted block with Initial Vector. And this
		 * process goes like a chain in the for loop as you see.
		 **/
		byte[] plainByte = plainText.getBytes();
		byte[] array_3 = new byte[16];
		Cipher aesCipher;
		blocks.add(iv);
		for (int j = 0; j < plainByte.length; j++) {

			int i = 0;
			for (byte b : iv)
				array_3[i] = (byte) (b ^ plainByte[i++]); // XORing
			aesCipher = Cipher.getInstance("AES/ECB/NoPadding");
			aesCipher.init(Cipher.ENCRYPT_MODE, skey);
			iv = aesCipher.doFinal(array_3);
			blocks.add(iv); // We are string these blocks for decryption purpose
		}

		return iv;
	}

	/**
	 * Alright, this part was the most difficult part because after several attempts
	 * I realized that only way of decrypting is storing blocks of cipher text
	 * that's why after this I created Arraylist called blocks in order to achieve
	 * this. Honestly, I spent so much time on this code so that in this part, even
	 * I didn't know what I did in XORing part but it worked xD
	 **/
	public static byte[] decryptedText(int encKey, byte[] encryptedText) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		
		String keyFile = encKey + "000000000000000";
		if(keyFile.length()>16)
			keyFile=keyFile.substring(0,16);
		byte[] keyb = new byte[16];
		keyb = keyFile.getBytes();
		SecretKeySpec skey = new SecretKeySpec(keyb, "AES");

		byte[] encryptedByte = encryptedText;
		byte[] array_3 = new byte[16];
		byte[] plainByte = new byte[16];
		Cipher aesCipher;

		for (int j = 0; j < encryptedByte.length; j++) {
			aesCipher = Cipher.getInstance("AES/ECB/NoPadding");
			aesCipher.init(Cipher.DECRYPT_MODE, skey);
			plainByte = aesCipher.doFinal(blocks.get(encryptedByte.length)); // Decrypting our block

			int i = 0;
			for (byte b : blocks.get(j))
				array_3[i] = (byte) (b ^ plainByte[i++]); // XORing of our blocks

		}

		return array_3;

	}

	/**
	 * This function belongs to "mkyong" who is the founder of mkyong.com. Function
	 * code is from "https://mkyong.com/java/java-how-to-convert-bytes-to-hex/
	 **/
	public static String bytesToHex(byte[] hashInBytes) {

		StringBuilder sb = new StringBuilder();
		for (byte b : hashInBytes) {
			sb.append(String.format("%02x", b));
		}
		return sb.toString();
	}

}
