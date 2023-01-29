package keyproduce;

import java.awt.RenderingHints.Key;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.util.encoders.Base64Encoder;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.junit.Before;
import org.junit.jupiter.api.Test;

public class KeyProduce {
	
	/**
	 * issuer    證書頒發者
	 * subject   證書使用者
	 * 
	 * DN：Distinguish Name
	 * 格式：CN=姓名,OU=組織單位名稱,O=組織名稱,L=城市或區域名稱,ST=市平稱,C=國家雙字母
	 *
	 */
	
	private static final String KEY_PAIR_ALG=""	;
	private static final String SIG_ALG="";
	private static final String DN_TAIPEI="";
	private static final String DN_LIZ="CN=LiZ,OU=Persh,O=Persh,L=Taipei,ST=TW";

	private static final String DN_CA="CN=LiZ,OU=Persh,O=Persh,L=Taipei,ST=TW";
	
	private static Map<String,String> algorithmMap=new HashMap<>();
	
	static {
		algorithmMap.put("1.2.840.113549.1.1.5",SIG_ALG);	
		algorithmMap.put("1.2.840.113549.1.1.1",KEY_PAIR_ALG);
	}
	
	@Before
	public void before() {
	Provider provider=new BouncyCastleProvider();	
	Security.addProvider(provider);
	}
	@Test
	public void testGenRootKeyPair(String[] args) {
		try {
			KeyPairGenerator keyPairGenerator=KeyPairGenerator.getInstance(KEY_PAIR_ALG);
			keyPairGenerator.initialize(4096);
			KeyPair keyPair=keyPairGenerator.generateKeyPair();
			writeObject("",keyPair.getPublic());
			writeObject("",keyPair.getPrivate());
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
	
	@Test
	public void testZhangsanKeyPair()throws Exception{
		KeyPairGenerator keyPairGenerator=KeyPairGenerator.getInstance(KEY_PAIR_ALG);
		keyPairGenerator.initialize(4096);
		KeyPair keyPair=keyPairGenerator.generateKeyPair();
		writeObject("",keyPair.getPublic());
		writeObject("",keyPair.getPrivate());
	}

	@Test
	public void testGenRootCert()throws Exception{
		String caPassword = "passw0rd";
		KeyStore ks = KeyStore.getInstance("PKCS12");
		ks.load(new FileInputStream( new File("PKCS12Path")),caPassword.toCharArray());
//		X509Certificate cert = (X509Certificate)ks.getCertificate(sAlias);
//		Base64Encoder encoder=new Base64Encoder();
//		String yourB64Certificate = encoder.encodeBuffer(cert.getEncoded());
		
		
		X509V3CertificateGenerator certGen=new X509V3CertificateGenerator();
		certGen.setIssuerDN(new X500Principal(DN_CA));
		certGen.setNotAfter(new Date(System.currentTimeMillis()+100*24*60*60*1000));
		certGen.setNotBefore(new Date());
		certGen.setPublicKey(getRootPublicKey());
		certGen.setSerialNumber(BigInteger.TEN);
		certGen.setSignatureAlgorithm(SIG_ALG);
		certGen.setSubjectDN(new X500Principal(DN_CA));
		X509Certificate certificate=certGen.generate(getRootPrivateKey());
		PKCS12BagAttributeCarrier bagAttr=(PKCS12BagAttributeCarrier)certificate;
		bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,new DERBMPString(""));
		
		writeFile("*/*/ca.cer",certificate.getEncoded());
		
	}
	
	@Test
	public void testGenRootCertWithBuilder()throws Exception{
		final AlgorithmIdentifier sigAlgId=new DefaultSignatureAlgorithmIdentifierFinder().find(SIG_ALG);
		final AlgorithmIdentifier digAlgId=new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
		
		PublicKey publicKey=getRootPublicKey();
		PrivateKey privateKey=getRootPrivateKey();
		
		X500Name issuer=new X500Name(DN_CA);
		BigInteger serial=BigInteger.TEN;
		Date notBefore=new Date();
		Date notAfter=new Date(System.currentTimeMillis()+100*24*60*60*1000);
		X500Name subject=new X500Name(DN_CA);
		AlgorithmIdentifier algId=AlgorithmIdentifier.getInstance(PKCSObjectIdentifiers.rsaEncryption.toString());
		System.out.println(algId.getAlgorithm());
	
		AsymmetricKeyParameter publicKeyParameter=PublicKeyFactory.createKey(publicKey.getEncoded());
		SubjectPublicKeyInfo publicKeyInfo=SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKeyParameter);
		X509v3CertificateBuilder x509v3CertificateBuilder=new X509v3CertificateBuilder(issuer,serial,notBefore,notAfter,subject,publicKeyInfo);
	
		BcRSAContentSignerBuilder contentSignerBuilder=new BcRSAContentSignerBuilder(sigAlgId,digAlgId);
		
		AsymmetricKeyParameter privateKeyParameter=PrivateKeyFactory.createKey(privateKey.getEncoded());
		ContentSigner contentSigner=contentSignerBuilder.build(privateKeyParameter);
	
		X509CertificateHolder certificateHolder=x509v3CertificateBuilder.build(contentSigner);
		Certificate certificate =certificateHolder.toASN1Structure();
		
		writeFile("*/*/ca.cer",certificate.getEncoded());
		
	}

	@Test
	public void testgenZhangsnacert()throws Exception{
		X509V3CertificateGenerator certGen=new X509V3CertificateGenerator();
		certGen.setIssuerDN(new X500Principal(DN_CA));
		certGen.setNotAfter(new Date(System.currentTimeMillis()+100*24*60*60*1000));
		certGen.setNotBefore(new Date());
		certGen.setPublicKey(getZhangsanPublicKey());
		certGen.setSerialNumber(BigInteger.TEN);
		certGen.setSubjectDN(new X500Principal(DN_LIZ));
		X509Certificate certificate=certGen.generate(getRootPrivateKey());
		writeFile("*/*/liz.cer",certificate.getEncoded());
	}
	
	
	@Test
	public void testVerifyRootCert()throws Exception{
		CertificateFactory certificateFactory=CertificateFactory.getInstance("X.509");
		FileInputStream inStream=new FileInputStream("*/*/ca.cer");
		X509Certificate certificate=(X509Certificate)certificateFactory.generateCertificate(inStream);

		System.out.println(certificate);
		Signature signature=Signature.getInstance(certificate.getSigAlgName());
		signature.initVerify(certificate);
		signature.update(certificate.getTBSCertificate());
		boolean legal=signature.verify(certificate.getSignature());
		System.out.println(legal);
	}
	
	@Test
	public void testVerifyZhangsnaCert() throws Exception{
		CertificateFactory certificateFactory=CertificateFactory.getInstance("X.509");
		FileInputStream inStream=new FileInputStream("*/*/liz.cer");
		X509Certificate certificate=(X509Certificate)certificateFactory.generateCertificate(inStream);
		System.out.println(certificate.getPublicKey().getClass());
		Signature signature=Signature.getInstance(certificate.getSigAlgName());
		signature.initVerify(getRootPublicKey());
		signature.update(certificate.getTBSCertificate());
		boolean legal=signature.verify(certificate.getSignature());
		System.out.println(legal);
	}

	@Test
	public void testGenCSR() throws Exception{
		X500Name subject=new X500Name(DN_LIZ);
		AsymmetricKeyParameter keyParameter=PrivateKeyFactory.createKey(getZhangsanPrivateKey().getEncoded());
		SubjectPublicKeyInfo publicKeyInfo=SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(keyParameter);
		PKCS10CertificationRequestBuilder certificationRequestBuilder=new PKCS10CertificationRequestBuilder(subject,publicKeyInfo);
		final AlgorithmIdentifier sigAlgId=new DefaultSignatureAlgorithmIdentifierFinder().find(SIG_ALG);
		final AlgorithmIdentifier digAlgId=new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
		BcRSAContentSignerBuilder contentSignerBuilder=new BcRSAContentSignerBuilder(sigAlgId,digAlgId);
		PKCS10CertificationRequest certificationRequest=certificationRequestBuilder.build(contentSignerBuilder.build(keyParameter));
	
		System.out.println(certificationRequest);
		writeFile("*/*/liz.csr",certificationRequest.getEncoded());
		
	}
	
	@Test
	public void testZhangsanCertWithCSR()throws Exception{
		byte[] encoded=readFile("*/*/liz.csr");
		PKCS10CertificationRequest certificationRequest=new PKCS10CertificationRequest(encoded);
		
		RSAKeyParameters parameter=(RSAKeyParameters)PublicKeyFactory.createKey(certificationRequest.getSubjectPublicKeyInfo());
		RSAPublicKeySpec keySpec=new RSAPublicKeySpec(parameter.getModulus(),parameter.getExponent());
		String algorithm=algorithmMap.get(certificationRequest.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm().toString());
		PublicKey publicKey=KeyFactory.getInstance(algorithm).generatePublic(keySpec);
		System.out.println(certificationRequest.getSubject());
		X509V3CertificateGenerator certGen=new X509V3CertificateGenerator();
		certGen.setIssuerDN(new X500Principal(DN_CA));
		certGen.setNotAfter(new Date(System.currentTimeMillis()+100*24*60*60*1000));
		certGen.setNotBefore(new Date());
		certGen.setPublicKey(publicKey);
		certGen.setSerialNumber(BigInteger.TEN);
		certGen.setSignatureAlgorithm(algorithmMap.get(certificationRequest.getSignatureAlgorithm().getAlgorithm().toString()));
		certGen.setSubjectDN(new X500Principal(certificationRequest.getSubject().toString()));
		X509Certificate certificate=certGen.generate(getRootPrivateKey());
		writeFile("*/*/liz.cer",certificate.getEncoded());
		
	}
	
	public void writeFile(String path,byte[] content)throws Exception{
		FileOutputStream fos=new FileOutputStream(path);
		fos.write(content);
		fos.close();
	}
	
	public PrivateKey getRootPrivateKey()throws Exception{
		return PrivateKey.class.cast(readKey("*/*/Digicert.private"));
	}
	
	public PublicKey getRootPublicKey()throws Exception{
		return PublicKey.class.cast(readKey("*/*/Digicert.public"));
	}
	
	public PrivateKey getZhangsanPrivateKey()throws Exception{
		return PrivateKey.class.cast(readKey("*/*/liz.private"));
	}
	
	public PublicKey getZhangsanPublicKey() throws Exception{
		return PublicKey.class.cast(readKey("*/*/liz.public"));
	}
	
	public byte[] readFile(String path)throws Exception{
		FileInputStream cntInput=new FileInputStream(path);
		ByteArrayOutputStream baos=new ByteArrayOutputStream();
		int b=-1;
		while((b=cntInput.read())!=-1) {
			baos.write(b);
		}
		cntInput.close();
		byte[] contents=baos.toByteArray();
		baos.close();
		return contents;
		
	}
	
	private void writeObject(String path,Object object) throws Exception, IOException {
		ObjectOutputStream oos=new ObjectOutputStream(new FileOutputStream(path));
		oos.writeObject(object);
		oos.close();
	}
	
	private Object readObject(String path) throws Exception, IOException {
		ObjectInputStream ois=new ObjectInputStream(new FileInputStream(path));
		Object obj=ois.readObject();
		ois.close();
		return obj;
	}

	private Key readKey(String path)throws Exception{
		ObjectInputStream ois=new ObjectInputStream(new FileInputStream(path));
		Key key=Key.class.cast(ois.readObject());
		ois.close();
		return key;
	}
	
}
