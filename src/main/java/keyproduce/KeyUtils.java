package keyproduce;

import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

public class KeyUtils {
	private static KeyFactory keyFactory;
	static {
		try {
			keyFactory = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	
//	產Private、Public。
	public KeyPair getGenedKeyPair(String certName,int keySize,String keyAlgorithm) {
		KeyPairGenerator keyPairGen = null;
		try {
			keyPairGen = KeyPairGenerator.getInstance(keyAlgorithm);
			
			keyPairGen.initialize(keySize,new SecureRandom());
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return keyPairGen.genKeyPair();
	}
	
//	取KeyPair
	private String getEncodedKeyString(RSAKey rsaKey) {
		Encoder encode=Base64.getEncoder();
		return (rsaKey instanceof RSAPublicKey)?encode.encodeToString(((RSAPublicKey)rsaKey).getEncoded()):encode.encodeToString(((RSAPrivateKey)rsaKey).getEncoded());
	}
	private byte[] getDecodedKeyBytes(String encodedKeyString) throws UnsupportedEncodingException {
		Decoder decode=Base64.getDecoder();
		
		return decode.decode(encodedKeyString);
	}
	

	private <T>Key recoverToPublicKey(byte[] keyBytes,T keyType) throws InvalidKeySpecException {
		X509EncodedKeySpec x509EncodedKeySpec=new X509EncodedKeySpec(keyBytes);
		return (keyType instanceof PublicKey)? keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes)):keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
	}
	
	private StringBuffer exportPublicEncodedString(String encodedString) {
		StringBuffer sbr=new StringBuffer();
		sbr.append("-----BEGIN CERTIFICATE-----\n");
		sbr.append(encodedString);
		sbr.append("-----END CERTIFICATE-----\n");
		return sbr;
	}
	private StringBuffer exportPrivateEncodedString(String encodedString) {
		StringBuffer sbr=new StringBuffer();
		sbr.append("-----BEGIN RSA PRIVATE KEY-----\n");
		sbr.append(encodedString);
		sbr.append("-----END RSA PRIVATE KEY-----\n");
		return sbr;
	}
	
}
