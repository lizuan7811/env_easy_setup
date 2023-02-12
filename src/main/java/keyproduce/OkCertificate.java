package keyproduce;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;
import javax.security.cert.*;

import org.apache.logging.log4j.util.Strings;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.util.ReflectionUtils;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;

import java.util.Base64.*;

public class OkCertificate {
	private static Path keyPath = Paths.get("C://Users/ASUS/Desktop/");

	private final String ISSUER = "issuer";
	private final String SUBJ = "subj";
	private final String ISSUER_VALUE = "CN=192.168.112.112,CN=192.168.112.113,CN=192.168.112.114, OU=JavaSoft, O=Sun Microsystems, C=US";
	private final String SUBJECT_VALUE = "CN=192.168.112.112,CN=192.168.112.113,CN=192.168.112.114, OU=JavaSoft, O=Sun Microsystems, C=US";
	private Set<String> subjFieldSet = new HashSet<>();
	private final static BCStyle INSTANCE = (BCStyle) BCStyle.INSTANCE;

	/**
	 * 產最初始的憑證並取KeyPair
	 */
	public KeyPair generateRootCA(String caName, int encrypSize, String specifiedAlgorithm) {
		try {
//			產生最原始用來簽證用的publicKey、privateKey
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(specifiedAlgorithm);
			keyPairGenerator.initialize(encrypSize, new SecureRandom());
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
//			取publicKey、privateKey
			RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
			RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
//			將key轉碼為Base64
			Encoder encode = Base64.getEncoder();
			Decoder decode = Base64.getDecoder();
			String publicKeyString = encode.encodeToString(rsaPublicKey.getEncoded());
			String privateKeyString = encode.encodeToString(rsaPrivateKey.getEncoded());
//			列印編碼後的key
//			System.out.println(rsaPublicKey);
//			System.out.println(">>>\t" + publicKeyString);
//			System.out.println();
//			System.out.println(rsaPrivateKey);
//			System.out.println(">>>\t" + privateKeyString);

//			可以是RSA/jks/PKCS12...
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//			為了符合X509，須先取得X509格式的類別
			byte[] keyBytes = decode.decode(publicKeyString);
			X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);
			// 使用KeyFactory產符合x509格式的publicKey。
//			keyFactory.generatePublic(x509EncodedKeySpec);
			// 使用KeyFactory產符合pkcs8格式的privateKey，使用不同的keySpec產出不同格式的key。
			keyBytes = decode.decode(privateKeyString);
			PKCS8EncodedKeySpec pKCS8EncodedkeySpec = new PKCS8EncodedKeySpec(keyBytes);
			PrivateKey privateKey = keyFactory.generatePrivate(pKCS8EncodedkeySpec);
// 			要使用key加密時，若key是以Base64編碼後的資料，則需先解編碼，再轉為key的格式才行。
			// 用來加密資料使用
//			將publicKey放入Cipher，初始化加密使用的Cipher工具(用作傳輸使用，一定只會用pulicKey來加密，因為privateKey具備publicKey的資料，所以不會用privateKey加密資料。
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(cipher.ENCRYPT_MODE, keyPair.getPublic());
//			已經有證書的情況下，可以使用x509CertificateHolder傳入x509v3CertificateBuilder產生Certificate。
//			X509CertificateHolder x509CertificateHolder=new X509CertificateHolder(Certificate.getInstance(x509EncodedKeySpec));
//			byte[] publicKeyBytes=new byte[publicKeyString.getBytes().length];
			StringBuffer stringBuffer = new StringBuffer();
			stringBuffer.append("-----BEGIN CERTIFICATE-----\n");
			stringBuffer.append(publicKeyString);
			stringBuffer.append("-----END CERTIFICATE-----\n");

//			X500Principal issuer=new X500Principal("CN=192.168.112.112,CN=192.168.112.113,CN=192.168.112.114, OU=JavaSoft, O=Sun Microsystems, C=US");
//			X500Principal subject=new X500Principal("CN=192.168.112.112,CN=192.168.112.113,CN=192.168.112.114, OU=JavaSoft, O=Sun Microsystems, C=US");
//			X509v3CertificateBuilder x509CertGen = new X509v3CertificateBuilder(X500Name.getInstance(issuer.getEncoded()), BigInteger.TEN,new Date(), new Date(System.currentTimeMillis() + 100 * 24 * 60 * 60 * 1000),X500Name.getInstance(subject.getEncoded()), SubjectPublicKeyInfo.getInstance(rsaPublicKey.getEncoded()));

//			ASN1ObjectIdentifier aSN1ObjectIdentifier=BCStyle.BUSINESS_CATEGORY;
//			ASN1EncodableVector aSN1EncodableVector=new ASN1EncodableVector();

//			ASN1OctetString aSN1OctetString=new DEROctetString("CN=Duke, OU=JavaSoft, O=Sun Microsystems, C=US".getBytes());
//			aSN1EncodableVector.add(aSN1OctetString);

//			將資料輸入，先建立產生cert使用的certbuilder
//			使用X500NameBuilder建立X500Name
			X500Name x500NameIsser = ((X500NameBuilder) getX500NameBuider(ISSUER, ISSUER_VALUE).get(ISSUER)).build();
			X500Name x500NameSubject = ((X500NameBuilder) getX500NameBuider(SUBJ, SUBJECT_VALUE).get(SUBJ)).build();
			X509v3CertificateBuilder x509CertGen = new X509v3CertificateBuilder(x500NameIsser, BigInteger.TEN,
					new Date(), new Date(System.currentTimeMillis() + 100 * 24 * 60 * 60 * 1000), x500NameSubject,
					SubjectPublicKeyInfo.getInstance(rsaPublicKey.getEncoded()));

//			建立一個extention生成工具
			ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();

//			extensionsGenerator.addExtension(new ASN1ObjectIdentifier("2.5.29.37"), true,new DERSequence(KeyPurposeId.anyExtendedKeyUsage));
			BasicConstraints basicConstraints = new BasicConstraints(false);
			getBuildedExtention();
//			getExtnASN1OidFromName("");

			// Extension extension=new
			// Extension(Extension.authorityKeyIdentifier,ASN1Boolean.TRUE,ASN1OctetString.getInstance(ASN1TaggedObject.getInstance(subject),false));
//			extensionsGenerator.addExtension();
//			ASN1ObjectIdentifier aSN1ObjectIdentifier= Extension.authorityKeyIdentifier;

//			Extension extention=new AuthorityKeyIdentifierExtension(new KeyIdentifier(DerValue.tag_Integer), new GeneralNames(DerValue.tag_Integer),new SerialNumber(BigInteger.TEN));
//			 AuthorityKeyIdentifierExtension(KeyIdentifier kid, GeneralNames names,SerialNumber sn)

//			AuthorityKeyIdentifier AuthorityKeyIdentifier=	AuthorityKeyIdentifier.getInstance(null);
//			增加擴展內容
			Extensions extentions = extensionsGenerator.generate();
//			Extension extension=new Extension(aSN1ObjectIdentifier, null, null);
//			要對憑證增加Extention是從Builder這裡增加進去
//			x509CertGen.addExtension(extentions.getExtension(aSN1ObjectIdentifier));
//			x509CertGen.addExtension(null);
//			取得簽證用的算法名稱
			String keyAlgorithm = rsaPrivateKey.getAlgorithm();
			String signatureAlgorithm = Strings.EMPTY;
			if (keyAlgorithm.equals("RSA")) {
				signatureAlgorithm = "SHA512withRSA";
			}

//			EXtension是用來要申請簽證使用的資料，產出的檔案為CSR

			ContentSigner sigGen = new JcaContentSignerBuilder(signatureAlgorithm).build(rsaPrivateKey);

			X509CertificateHolder x509CertHolder = x509CertGen
					.build(new JcaContentSignerBuilder(signatureAlgorithm).build(rsaPrivateKey));
			System.out.println(">>>\t" + x509CertHolder.getExtension(null));

			System.out.println(">>>ExtensionOID\t" + x509CertHolder.getExtensionOIDs());

			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			X509Certificate x509Cert = (X509Certificate) certFactory
					.generateCertificate(new ByteArrayInputStream(x509CertHolder.getEncoded()));
			System.out.println(x509Cert);
			System.out.println();
			System.out.println();

			System.out.println(x509Cert.getIssuerDN());
			System.out.println();
			System.out.println();

//			Signature RSASignature=Signature.getInstance("");
			System.out.println(x509Cert.getBasicConstraints());
			System.out.println();
			System.out.println();

			System.out.println(x509Cert.getSigAlgOID());
			System.out.println();
			System.out.println();

			System.out.println(x509Cert.getType());
			System.out.println();
			System.out.println();

			System.out.println(x509Cert.getVersion());
			System.out.println();
			System.out.println();

			System.out.println(x509Cert.getSigAlgName());
			System.out.println();
			System.out.println();

			System.out.println(x509Cert.getIssuerUniqueID());
			System.out.println();
			System.out.println();

			System.out.println(x509Cert.getIssuerX500Principal());
			System.out.println();
			System.out.println();

			System.out.println(x509Cert.getExtendedKeyUsage());
			System.out.println();
			System.out.println();

			System.out.println(x509Cert.getExtensionValue(signatureAlgorithm));
			System.out.println();
			System.out.println();

//			-----BEGIN CERTIFICATE-----, and must be bounded at the end by -----END CERTIFICATE-----
//			InputStream byteArrayInputStream=new ByteArrayInputStream(stringBuffer.toString().getBytes());
//			System.out.println(Objects.isNull(byteArrayInputStream));
//			沒有已存在的憑證情況下，需先建立x500Name、Date、
//			CertificateFactory certificateFactory=CertificateFactory.getInstance("X.509");
//			Certificate certificate=  certificateFactory.generateCertificate(byteArrayInputStream);
//			System.out.println("\tCertificate\t"+certificate);

//			X500Name x500Name=new X500Name("CN=192.168.1.1");
//			SubjectPublicKeyInfo.getInstance(null);

//			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
//			System.out.println(String.format("%s%s.crt", keyPath.toAbsolutePath(), caName));
//			writeObject(String.format("%s/%s.crt", keyPath.toAbsolutePath(), caName), keyPair.getPublic());
//			System.out.println(new String(keyPair.getPrivate().getFormat()));
//
//			byte[] bytes = cipher.doFinal("Test gen Keys".getBytes());
//			System.out.println(bytes);

//			writeObject(String.format("%s/%s.key", keyPath.toAbsolutePath(), caName), keyPair.getPrivate());
			return keyPair;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public void trytryk() {
		// 根据Certificate生成KeyStore
		try {
			InputStream certificateStream = new FileInputStream("");
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			KeyStore keyStore = KeyStore.getInstance("PKCS12");
			keyStore.load(null);
			keyStore.setCertificateEntry("certificate", certificateFactory.generateCertificate(certificateStream));
			// 加载jks文件，并生成KeyStore
			KeyStore trustKeyStore = KeyStore.getInstance("jks");
			FileInputStream trustKeyStoreFile = new FileInputStream("/root/trustKeyStore.jks");
			trustKeyStore.load(trustKeyStoreFile, "password".toCharArray());
		} catch (CertificateException | KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public void producePPKeys() {

		KeyPairGenerator keyPairGenerator = null;
		try {
//			產RSA KeyPairGenerator
			keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//			設定Size
			keyPairGenerator.initialize(4096);
//			產Keypair並取得公私鑰
			KeyPair keyPair = keyPairGenerator.genKeyPair();
			RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
			RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
//			System.out.println(rsaPublicKey);
//			System.out.println(rsaPrivateKey);
//			Cipher加密方式
//			Cipher cipher=Cipher.getInstance("RSA");
//			cipher.init(Cipher.ENCRYPT_MODE,rsaPublicKey);
//			byte[] byts=cipher.doFinal("testpass".getBytes());
//			System.out.println(new String(byts));
//			cipher.init(Cipher.DECRYPT_MODE,rsaPrivateKey);
//			byts=cipher.doFinal(byts);
//			System.out.println(new String(byts));
//			System.out.println(rsaPublicKey.getModulus());
//			System.out.println(rsaPrivateKey.getModulus());

//  		使用BASE64編碼解碼
			java.util.Base64.Decoder decoder = java.util.Base64.getDecoder();
			java.util.Base64.Encoder encoder = java.util.Base64.getEncoder();
			String publicKeyString = encoder.encodeToString(rsaPublicKey.getEncoded());
			String privateKeyString = encoder.encodeToString(rsaPrivateKey.getEncoded());

//			System.out.println(publicKeyString);

//			System.out.println("==================================");
//
//			System.out.println(privateKeyString);
//	建立產key的工具工具
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//			公鑰解碼方式
			byte[] keyBytes = decoder.decode(publicKeyString);
			EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);
			PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
//			私鑰解碼方式
			keyBytes = decoder.decode(privateKeyString);
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyBytes);
			PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);

//			System.out.println(publicKey);
//			System.out.println(privateKey);

//			KeyStore keyStore=KeyStore.getInstance("PKCS12");	
//			keyStore.load(null);;

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	private Map<String, X500NameBuilder> getX500NameBuider(String identifierName, String x500SourceString) {

		Map<String, X500NameBuilder> x500NameBuildMap = new HashMap<String, X500NameBuilder>();

//		@SuppressWarnings({ "rawtypes", "unchecked" })
//		Predicate<String> valid=new Predicate() {
//			@Override
//			public boolean test(Object t) {
//				String st=(String)t;
//				return subjFieldSet.contains(st.substring(0,st.indexOf('=')));
//			}
//		};

		Stream<String> streamSource = Stream.of(x500SourceString.split(","));
		X500NameBuilder x500NameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
		streamSource.filter(str -> {
			return valudResource(str);
		}).forEach(str -> {
			String attrName = str.substring(0, str.indexOf('=')).trim();
			String attrValue = str.substring(str.indexOf('=') + 1, str.length()).trim();
			ASN1ObjectIdentifier aSN1ObjectIdentifier = INSTANCE.attrNameToOID(attrName);
			x500NameBuilder.addRDN(aSN1ObjectIdentifier, attrValue);
		});
		if (identifierName.equals(ISSUER)) {
			x500NameBuildMap.put(ISSUER, x500NameBuilder);
		} else if (identifierName.equals(SUBJ)) {
			x500NameBuildMap.put(SUBJ, x500NameBuilder);
		}
		return x500NameBuildMap;
	}

	private void writeObject(String path, Object object) throws Exception, IOException {
		ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(path));
		oos.writeObject(object);
		oos.close();
	}

	public void genPkc12(String keyName, int keySize, String pass) {
		try {
			KeyStore keyStore = KeyStore.getInstance("PKCS12");
			keyStore.load(null, null);

			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(keySize);
			Key key = keyGen.generateKey();

			System.out.println(new String(key.getEncoded()));

			keyStore.setKeyEntry("", key, pass.toCharArray(), null);
			keyStore.store(new FileOutputStream(String.format("%s/%s.p12", keyPath.toAbsolutePath(), keyName)),
					pass.toCharArray());
		} catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException e) {
			e.printStackTrace();
		}
	}

	public List<Extension> getBuildedExtention() {
		try {
			Extension extension = Extension.class
					.getConstructor(ASN1ObjectIdentifier.class, ASN1Boolean.class, ASN1OctetString.class)
					.newInstance(null, ASN1Boolean.TRUE, null);

			List<String> extSourceList = getExtContentList(
					"authorityKeyIdentifier=keyid,issuer\r\n" + "basicConstraints=CA:FALSE\r\n"
							+ "keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment\r\n"
							+ "extendedKeyUsage = serverAuth\r\n" + "subjectAltName = @alt_names\r\n" + "\r\n"
							+ "[alt_names]\r\n" + "DNS.1=pibagt01\r\n" + "DNS.2=pibagt02\r\n" + "DNS.3=pibagt03\r\n"
							+ "DNS.5=localhost\r\n" + "IP.1 =192.168.112.90\r\n" + "IP.2 =192.168.112.91\r\n"
							+ "IP.3 =192.168.112.92");
//	    String [] altSubNames = access.getAlternativeName(5);
			List<Extension> extesionList = new ArrayList<Extension>();

			ASN1ObjectIdentifier subjectAlternativeName = Extension.subjectAlternativeName;

			int iPAddress = GeneralName.iPAddress;
			int dNSName = GeneralName.dNSName;

			List<GeneralName> altNames = new ArrayList<GeneralName>();

			extSourceList.stream().filter(str -> valudResource(str) && str.indexOf('[') != -1).forEach(extName -> {
				String[] tmpStr = extName.split("=");
				ASN1ObjectIdentifier aOid = getExtnASN1OidFromName(tmpStr[0].trim());
				if (tmpStr[1].indexOf(',') != -1) {
					tmpStr = tmpStr[1].split(",");
				}

				if (extName.contains("DNS") || extName.contains("SAN") || extName.contains("IP")) {
					
					
					
					GeneralName[] generalName=	new GeneralName[] { new GeneralName(GeneralName.dNSName, "dom.test.test") };
					
			GeneralNames generalNames=new GeneralNames(new GeneralName[] {
					new GeneralName(GeneralName.dNSName,"")
			});

			
				
				
					extesionList.add(new Extension(Extension.subjectAlternativeName, true,ASN1OctetString.getInstance(generalName)));
					
				} else {
					Arrays.asList(tmpStr).stream().forEach(str -> {
						extesionList.add(new Extension(aOid, ASN1Boolean.TRUE,
								ASN1OctetString.getInstance(subjectAlternativeName)));
					});
				}

			});

		} catch (InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException
				| NoSuchMethodException | SecurityException e) {
			e.printStackTrace();
		}
		return null;

	}

	public ASN1ObjectIdentifier getExtnASN1OidFromName(String asn1OidName) {
		ASN1ObjectIdentifier aSN1ObjectIdentifier = null;
		try {
			Extension extension = Extension.class
					.getConstructor(ASN1ObjectIdentifier.class, ASN1Boolean.class, ASN1OctetString.class)
					.newInstance(null, ASN1Boolean.TRUE, null);

			aSN1ObjectIdentifier = (ASN1ObjectIdentifier) Arrays.asList(Extension.class.getDeclaredFields()).stream()
					.map(field -> {
						try {
							ReflectionUtils.makeAccessible(field);
							return (ASN1ObjectIdentifier) field.get(extension);
						} catch (IllegalArgumentException | IllegalAccessException e) {
							e.printStackTrace();
							return null;
						}
					});
		} catch (InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException
				| NoSuchMethodException | SecurityException e1) {
			e1.printStackTrace();
		}

		return aSN1ObjectIdentifier;
	}

	@SuppressWarnings("rawtypes")
	public List<String> getExtContentList(String extSourceString) {
		Stream<String> extContentArr = Stream.of(extSourceString.replace("\r\n", "\n").split("\n"));

		List<String> extContentList = extContentArr.filter(str -> {
			return valudResource(str);
		}).collect(Collectors.toList());
		return extContentList;
	}

	private boolean valudResource(String resource) {
		return resource.contains("=") && resource.indexOf('=') != -1;
	}

//	public void genRSAP12(String keyName, int keySize, String pass) {
//		try {
//			KeyStore keyStore = KeyStore.getInstance("PKCS12");
////			keyStore.load(new FileInputStream(""),pass.toCharArray());
//			keyStore.load(null, null);
//
//			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("AES");
//			keyPairGenerator.initialize(keySize);
//			KeyPair keyPair = keyPairGenerator.genKeyPair();
//			System.out.println(new String(keyPair.getPrivate().getEncoded(), "ISO-8859-1"));
//			System.out.println(keyPair.getPublic().getFormat());
//			System.out.println(keyPair.getPublic().getAlgorithm());
//			System.out.println(keyPair.getPublic().toString());
////			System.out.println(">>>" + Base64.encode(keyPair.getPrivate().getEncoded()));
//
//			X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(X500Name.getInstance(""), BigInteger.TEN,
//					new Date(), new Date(System.currentTimeMillis() + 100 * 24 * 60 * 60 * 1000),
//					X500Name.getInstance(""), SubjectPublicKeyInfo.getInstance(""));
//
//			X509CertificateHolder x509CertificateHolder = certGen.build(new JcaContentSignerBuilder("SHA512WithRSA")
//					.setProvider(new BouncyCastleProvider()).build(keyPair.getPrivate()));
//
//		} catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException
//				| OperatorCreationException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//	}

	public KeyPair generateRsaKey() throws NoSuchAlgorithmException, UnsupportedEncodingException {

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		SecureRandom secureRandom = new SecureRandom();
		secureRandom.nextBytes(new byte[516]);
		keyGen.initialize(516, secureRandom);
		KeyPair keyPair = keyGen.genKeyPair();
		System.out.println(keyPair.getPrivate());
		System.out.println(new String(keyPair.getPrivate().getEncoded()));

		System.out.println(keyPair.getPublic());
		return keyPair;
	}

	public SecretKey generatorDesKey() throws UnsupportedEncodingException {

		SecretKey secretKey = null;

		try {
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			SecureRandom random = new SecureRandom();
			random.nextBytes(new byte[128]);
			System.out.println(random);
			keyGen.init(128, random);
			secretKey = keyGen.generateKey();
			System.out.println(secretKey.getAlgorithm());
			System.out.println(secretKey.getEncoded());
			System.out.println(secretKey.getFormat());
			System.out.println(new String(secretKey.getEncoded(), "utf-8"));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return secretKey;

	}

}
