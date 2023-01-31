package keyproduce;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class KeyCipher {
	
	/**
	 * 加密
	 */
	private void desAesEncrypt() {
		String input="";
		String key="";
		
		String algorithm="DES";
		String transformation="DES/CBC/PKCS5Padding";
		
		try {
			Cipher cipher=Cipher.getInstance(transformation);
			SecretKeySpec sks=new SecretKeySpec(key.getBytes(),algorithm);
			byte[] bytes=cipher.doFinal(input.getBytes());
			IvParameterSpec iv=new IvParameterSpec(key.getBytes());
			cipher.init(Cipher.ENCRYPT_MODE,sks,iv);
			System.out.println(new String(bytes));
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * 加密
	 */
	private void desAesEncrypt1() {
		String input="";
		String key="";
		String algorithm="DES";
		String transformation="DES";
		try {
			Cipher cipher=Cipher.getInstance(transformation);
			SecretKeySpec sks=new SecretKeySpec(key.getBytes(),algorithm);
			cipher.init(Cipher.ENCRYPT_MODE,sks);
			byte[] bytes=cipher.doFinal(input.getBytes());
			String encode=Base64.getEncoder().encodeToString(bytes);
			IvParameterSpec iv=new IvParameterSpec(key.getBytes());
			cipher.init(Cipher.ENCRYPT_MODE,sks,iv);
			System.out.println(encode);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * 解密
	 */
	private String descryptDES(String input,String key,String transformation,String algorithm)throws Exception{
		Cipher cipher=Cipher.getInstance(transformation);
		SecretKeySpec sks=new SecretKeySpec(key.getBytes(),algorithm);
		cipher.init(Cipher.DECRYPT_MODE,sks);
		byte[] bytes=cipher.doFinal(Base64.getDecoder().decode(input));
		return new String(bytes);
	}

}
