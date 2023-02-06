package keyproduce;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class OkCertificate {
	private static Path keyPath=Paths.get("C://Users/ASUS/Desktop/");

	/**
	 * 產最初始的憑證並取KeyPair
	 */
	public KeyPair generateRootCA(String caName,int encrypSize,String keyAlgorithm) {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyAlgorithm);
//			keyPairGenerator.initialize(encrypSize);
			keyPairGenerator.initialize(encrypSize, new SecureRandom());
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			
			Cipher cipher=Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(cipher.ENCRYPT_MODE, keyPair.getPublic());
			System.out.println(String.format("%s%s.crt",keyPath.toAbsolutePath(),caName));
			writeObject(String.format("%s/%s.crt",keyPath.toAbsolutePath(),caName), keyPair.getPublic());
			System.out.println(new String(keyPair.getPrivate().getFormat()));

			byte[] bytes=cipher.doFinal("Test gen Keys".getBytes());
			System.out.println(bytes);
			writeObject(String.format("%s/%s.key",keyPath.toAbsolutePath(),caName), keyPair.getPrivate());
			return keyPair;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	private void writeObject(String path, Object object) throws Exception, IOException {
		ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(path));
		oos.writeObject(object);
		oos.close();
	}
	
	
	public void genPkc12(String keyName,int keySize,String pass) {
		try {
			KeyStore keyStore=KeyStore.getInstance("PKCS12");
			keyStore.load(null,null);
			
			KeyGenerator keyGen=KeyGenerator.getInstance("AES");
			keyGen.init(keySize);
			Key key=keyGen.generateKey();
			
			System.out.println(new String(key.getEncoded()));
			
			keyStore.setKeyEntry("",key,pass.toCharArray(),null);
			keyStore.store(new FileOutputStream(String.format("%s/%s.p12",keyPath.toAbsolutePath(),keyName)),pass.toCharArray());
		} catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException e) {
			e.printStackTrace();
		}
	}
	
	public void genRSAP12(String keyName,int keySize,String pass) {
		try {
			KeyStore keyStore =KeyStore.getInstance("PKCS12");
//			keyStore.load(new FileInputStream(""),pass.toCharArray());
			keyStore.load(null,null);
			
			KeyPairGenerator keyPairGenerator=KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(keySize);
			KeyPair keyPair=keyPairGenerator.genKeyPair();
			
			X509v3CertificateBuilder certGen=new X509v3CertificateBuilder(X500Name.getInstance(""),BigInteger.TEN,new Date(),new Date(System.currentTimeMillis()+100*24*60*60*1000),X500Name.getInstance(""),SubjectPublicKeyInfo.getInstance(null));
			
			X509CertificateHolder x509CertificateHolder=certGen.build(new JcaContentSignerBuilder("SHA512WithRSA").setProvider(new BouncyCastleProvider()).build(keyPair.getPrivate()));
			
		} catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException | OperatorCreationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
