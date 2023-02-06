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
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.security.auth.x500.X500Principal;

import org.apache.catalina.security.SecurityUtil;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.x509.*;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.*;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.util.encoders.Base64Encoder;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.springframework.boot.autoconfigure.ldap.embedded.EmbeddedLdapProperties.Credential;

public class KeyProduce {

	/**
	 * issuer 證書頒發者 subject 證書使用者
	 * 
	 * DN：Distinguish Name 格式：CN=姓名,OU=組織單位名稱,O=組織名稱,L=城市或區域名稱,ST=市平稱,C=國家雙字母
	 *
	 */

	private static final String KEY_PAIR_ALG = "";
	private static final String SIG_ALG = "";
	private static final String DN_TAIPEI = "";
	private static final String DN_LIZ = "CN=LiZ,OU=Persh,O=Persh,L=Taipei,ST=TW";

	private static final String DN_CA = "CN=LiZ,OU=Persh,O=Persh,L=Taipei,ST=TW";

	private static Map<String, String> algorithmMap = new HashMap<>();

	static {
		algorithmMap.put("1.2.840.113549.1.1.5", SIG_ALG);
		algorithmMap.put("1.2.840.113549.1.1.1", KEY_PAIR_ALG);
	}
	
	
	
	private void KeyPairGen() {

//		String input="";
		String key = "";

		try {
//			Initializeing the KeyPairGenerator
			KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DSA");
//			初始化KeyPairGenerator物件
			keyPairGen.initialize(4096);
//			產生KeyPairGenerator, Generate the pair of keys
			KeyPair pair = keyPairGen.generateKeyPair();
//			取得公鑰
			PublicKey publicKey = pair.getPublic();
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
//			Initializing a Cipher object (初始化Cipher 物件)
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
//			將資料加入Cipher物件
			byte[] input = "Welcome to here".getBytes();
			cipher.update(input);
//			將資料執行加密，取得byte
			byte[] cipherText = cipher.doFinal();

		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException e) {
			e.printStackTrace();
		}

	}
	/**
	 * 產最初始的憑證並取KeyPair
	 */
	public KeyPair generateRootCA(String caName,int encrypSize,String keyAlgorithm) {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyAlgorithm);
			keyPairGenerator.initialize(encrypSize);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			Path keyPath=Paths.get("C://Users/ASUS/Desktop/");
			System.out.println(String.format("%s%s.crt",keyPath.toAbsolutePath(),caName));
			writeObject(String.format("%s/%s.crt",keyPath.toAbsolutePath(),caName), keyPair.getPublic());
			writeObject(String.format("%s/%s.key",keyPath.toAbsolutePath(),caName), keyPair.getPrivate());
			return keyPair;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
private String caPassword = "";
private KeyStore keyStore;
private String KEYSTORE_TYPE;
private String keyStorePath;
private KeyPair keyPair;
private Date startDate;
private Date endDate;

private PublicKey sourcePublicKey;
private PrivateKey sourcePrivateKey;

	public void generateCert() throws Exception {
		caPassword = "passw0rd";
		keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
		keyStore.load(new FileInputStream(new File(keyStorePath)), caPassword.toCharArray());
//		X509Certificate cert = (X509Certificate)ks.getCertificate(sAlias);
//		Base64Encoder encoder=new Base64Encoder();
//		String yourB64Certificate = encoder.encodeBuffer(cert.getEncoded());
		X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(X500Name.getInstance(DN_CA), BigInteger.TEN,
				new Date(), new Date(System.currentTimeMillis() + 100 * 24 * 60 * 60 * 1000),
				X500Name.getInstance(DN_CA), SubjectPublicKeyInfo.getInstance(null));
		X509CertificateHolder x509CertificateHolder =certGen.build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider(new BouncyCastleProvider())
						.build(keyPair.getPrivate()));
		
		
		
//		X509Certificate certificate=x509CertificateHolder.getSignature();
//		PKCS12BagAttributeCarrier bagAttr=(PKCS12BagAttributeCarrier)certificate;
//		bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,new DERBMPString(""));

//		writeFile("*/*/ca.cer",certificate.getEncoded());

	}

	public void testGenRootCertWithBuilder() throws Exception {
		final AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(SIG_ALG);
		final AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

		PublicKey publicKey = getRootPublicKey();
		PrivateKey privateKey = getRootPrivateKey();

		X500Name issuer = new X500Name(DN_CA);
		BigInteger serial = BigInteger.TEN;
		Date notBefore = new Date();
		Date notAfter = new Date(System.currentTimeMillis() + 100 * 24 * 60 * 60 * 1000);
		X500Name subject = new X500Name(DN_CA);
		AlgorithmIdentifier algId = AlgorithmIdentifier.getInstance(PKCSObjectIdentifiers.rsaEncryption.toString());
		System.out.println(algId.getAlgorithm());

		AsymmetricKeyParameter publicKeyParameter = PublicKeyFactory.createKey(publicKey.getEncoded());
		SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKeyParameter);
		X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(issuer, serial, notBefore,
				notAfter, subject, publicKeyInfo);

		BcRSAContentSignerBuilder contentSignerBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);

		AsymmetricKeyParameter privateKeyParameter = PrivateKeyFactory.createKey(privateKey.getEncoded());
		ContentSigner contentSigner = contentSignerBuilder.build(privateKeyParameter);

		X509CertificateHolder certificateHolder = x509v3CertificateBuilder.build(contentSigner);
		Certificate certificate = certificateHolder.toASN1Structure();

		writeFile("*/*/ca.cer", certificate.getEncoded());

	}

	public void testgenZhangsnacert() throws Exception {
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		certGen.setIssuerDN(new X500Principal(DN_CA));
		certGen.setNotAfter(new Date(System.currentTimeMillis() + 100 * 24 * 60 * 60 * 1000));
		certGen.setNotBefore(new Date());
		certGen.setPublicKey(getZhangsanPublicKey());
		certGen.setSerialNumber(BigInteger.TEN);
		certGen.setSubjectDN(new X500Principal(DN_LIZ));
		X509Certificate certificate = certGen.generate(getRootPrivateKey());
		writeFile("*/*/liz.cer", certificate.getEncoded());
	}

	public void testVerifyRootCert() throws Exception {
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		FileInputStream inStream = new FileInputStream("*/*/ca.cer");
		X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(inStream);

		System.out.println(certificate);
		Signature signature = Signature.getInstance(certificate.getSigAlgName());
		signature.initVerify(certificate);
		signature.update(certificate.getTBSCertificate());
		boolean legal = signature.verify(certificate.getSignature());
		System.out.println(legal);
	}

	public void testVerifyZhangsnaCert() throws Exception {
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		FileInputStream inStream = new FileInputStream("*/*/liz.cer");
		X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(inStream);
		System.out.println(certificate.getPublicKey().getClass());
		Signature signature = Signature.getInstance(certificate.getSigAlgName());
		signature.initVerify(getRootPublicKey());
		signature.update(certificate.getTBSCertificate());
		boolean legal = signature.verify(certificate.getSignature());
		System.out.println(legal);
	}

//	public void testGenCSR() throws Exception{
//		X500Name subject=new X500Name(DN_LIZ);
//		AsymmetricKeyParameter keyParameter=PrivateKeyFactory.createKey(getZhangsanPrivateKey().getEncoded());
//		SubjectPublicKeyInfo publicKeyInfo=SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(keyParameter);
//		PKCS10CertificationRequestBuilder certificationRequestBuilder=new PKCS10CertificationRequestBuilder(subject,publicKeyInfo);
//		final AlgorithmIdentifier sigAlgId=new DefaultSignatureAlgorithmIdentifierFinder().find(SIG_ALG);
//		final AlgorithmIdentifier digAlgId=new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
//		BcRSAContentSignerBuilder contentSignerBuilder=new BcRSAContentSignerBuilder(sigAlgId,digAlgId);
//		PKCS10CertificationRequest certificationRequest=certificationRequestBuilder.build(contentSignerBuilder.build(keyParameter));
//	
//		System.out.println(certificationRequest);
//		writeFile("*/*/liz.csr",certificationRequest.getEncoded());
//		
//	}

//	public void testZhangsanCertWithCSR()throws Exception{
//		byte[] encoded=readFile("*/*/liz.csr");
//		PKCS10CertificationRequest certificationRequest=new PKCS10CertificationRequest(encoded);
//		
//		RSAKeyParameters parameter=(RSAKeyParameters)PublicKeyFactory.createKey(certificationRequest.getSubjectPublicKeyInfo());
//		RSAPublicKeySpec keySpec=new RSAPublicKeySpec(parameter.getModulus(),parameter.getExponent());
//		String algorithm=algorithmMap.get(certificationRequest.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm().toString());
//		PublicKey publicKey=KeyFactory.getInstance(algorithm).generatePublic(keySpec);
//		System.out.println(certificationRequest.getSubject());
//		X509V3CertificateGenerator certGen=new X509V3CertificateGenerator();
//		certGen.setIssuerDN(new X500Principal(DN_CA));
//		certGen.setNotAfter(new Date(System.currentTimeMillis()+100*24*60*60*1000));
//		certGen.setNotBefore(new Date());
//		certGen.setPublicKey(publicKey);
//		certGen.setSerialNumber(BigInteger.TEN);
//		certGen.setSignatureAlgorithm(algorithmMap.get(certificationRequest.getSignatureAlgorithm().getAlgorithm().toString()));
//		certGen.setSubjectDN(new X500Principal(certificationRequest.getSubject().toString()));
//		X509Certificate certificate=certGen.generate(getRootPrivateKey());
//		writeFile("*/*/liz.cer",certificate.getEncoded());
//	}

	public void writeFile(String path, byte[] content) throws Exception {
		FileOutputStream fos = new FileOutputStream(path);
		fos.write(content);
		fos.close();
	}

	public PrivateKey getRootPrivateKey() throws Exception {
		return PrivateKey.class.cast(readKey("*/*/Digicert.private"));
	}

	public PublicKey getRootPublicKey() throws Exception {
		return PublicKey.class.cast(readKey("*/*/Digicert.public"));
	}

	public PrivateKey getZhangsanPrivateKey() throws Exception {
		return PrivateKey.class.cast(readKey("*/*/liz.private"));
	}

	public PublicKey getZhangsanPublicKey() throws Exception {
		return PublicKey.class.cast(readKey("*/*/liz.public"));
	}

	public byte[] readFile(String path) throws Exception {
		FileInputStream cntInput = new FileInputStream(path);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		int b = -1;
		while ((b = cntInput.read()) != -1) {
			baos.write(b);
		}
		cntInput.close();
		byte[] contents = baos.toByteArray();
		baos.close();
		return contents;

	}

	private void writeObject(String path, Object object) throws Exception, IOException {
		ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(path));
		oos.writeObject(object);
		oos.close();
	}

	private Object readObject(String path) throws Exception, IOException {
		ObjectInputStream ois = new ObjectInputStream(new FileInputStream(path));
		Object obj = ois.readObject();
		ois.close();
		return obj;
	}

	private Key readKey(String path) throws Exception {
		ObjectInputStream ois = new ObjectInputStream(new FileInputStream(path));
		Key key = Key.class.cast(ois.readObject());
		ois.close();
		return key;
	}

//	==================================================
	public static X509Certificate generateCertificate(KeyPair keyPair)
			throws CertificateException, OperatorCreationException {
		X500Name x500Name = new X500Name("CN=Annoying Wrapper");
		SubjectPublicKeyInfo subPublicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
		final Date start = new Date();
		final Date until = Date
				.from(LocalDate.now().plus(365, ChronoUnit.DAYS).atStartOfDay().toInstant(ZoneOffset.UTC));
		final X509v3CertificateBuilder builder = new X509v3CertificateBuilder(x500Name,
				new BigInteger(10, new SecureRandom()), start, until, x500Name, subPublicKeyInfo);
		ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").setProvider(new BouncyCastleProvider())
				.build(keyPair.getPrivate());
		final X509CertificateHolder holder = builder.build(signer);
		X509Certificate x509Cert = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider())
				.getCertificate(holder);

		return x509Cert;
	}

	private static void generate(String fqdn, KeyPair keyPair, SecureRandom secureRandom, Date notBefore, Date notAfter)
			throws Exception {

		X500Name x500Name = new X500Name("CN=" + fqdn);
		X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(x500Name, new BigInteger(64, secureRandom),
				notBefore, notAfter, x500Name, keyPair.getPublic());
		ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(keyPair.getPrivate());
		X509CertificateHolder certHolder = builder.build(signer);
		X509Certificate cert = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider())
				.getCertificate(certHolder);
		cert.verify(keyPair.getPublic());
//		return newSelfSignedCertificate(fqdn,keyPair.getPrivate(),cert);

	}

	private static X509Certificate generateIssuedCertificate(String dn, PublicKey publicKey, String issuerDn,
			PrivateKey issuerKey) throws OperatorCreationException, CertificateException {

		ContentSigner sigGen = new JcaContentSignerBuilder("SIGNATURE_ALGORITHM")
				.setProvider(new BouncyCastleProvider()).build(issuerKey);
		SubjectPublicKeyInfo subPublicKeyInfo = SubjectPublicKeyInfo.getInstance(sigGen);
		Date startDate = new Date("YESTERDAY");
		Date endDate = new Date("ONE_YEAR_FROM_NOW");
		X509v3CertificateBuilder v3CertGen = new X509v3CertificateBuilder(new X500Name(issuerDn), BigInteger.TEN,
				startDate, endDate, new X500Name(dn), subPublicKeyInfo);
		X509CertificateHolder certificateHolder = v3CertGen.build(sigGen);
		return new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider())
				.getCertificate(certificateHolder);
	}

	public X509CertificateHolder generateCertificate(String subjectName, PublicKey subjectPublicKey) throws OperatorCreationException {
		SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(subjectPublicKey.getEncoded());
		BigInteger serial = BigInteger.valueOf(new SecureRandom().nextLong());
		Date startDate = Date.from(Instant.now().minus(1l, ChronoUnit.HOURS));
		Date endDate = Date.from(startDate.toInstant().plus(1l, ChronoUnit.DAYS));
		X500NameBuilder subject = new X500NameBuilder();
		subject.addRDN(BCStyle.CN, subjectName);
		subject.addRDN(BCStyle.O, "orgName");
		X509v3CertificateBuilder v3CertGen = new X509v3CertificateBuilder(subject.build(), serial, startDate, endDate,
				subject.build(), subjectPublicKeyInfo);
		
		  AlgorithmIdentifier sigAlgId = v3CertGen.build(null).getSignatureAlgorithm();
		  AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
	     ContentSigner sigGen = new BcECContentSignerBuilder(sigAlgId, digAlgId).build(
	    		 new AsymmetricKeyParameter(true));
		return v3CertGen.build(sigGen);
	}

	
	
}
