package keyproduce;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.logging.log4j.util.Strings;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.util.ReflectionUtils;

public class KeyUtils {

	private static KeyFactory keyFactory;

	private PublicKey publicKey;
	private PrivateKey privateKey;
	private final static BCStyle INSTANCE = (BCStyle) BCStyle.INSTANCE;
	private final String ISSUER = "issuer";
	private final String SUBJ = "subj";
	private final String ISSUER_VALUE = "CN=192.168.112.112,CN=192.168.112.113,CN=192.168.112.114, OU=JavaSoft, O=Sun Microsystems, C=US";
	private final String SUBJECT_VALUE = "CN=192.168.112.112,CN=192.168.112.113,CN=192.168.112.114, OU=JavaSoft, O=Sun Microsystems, C=US";
	private final long validRange = 365 * 24 * 3600 * 1000L;
	private int validYears = 0;
	static {
		try {
			keyFactory = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

	public KeyUtils() {
		initkeys("default-ca", 4096, "RSA");
		this.validYears = 10;
	}

	public KeyUtils(String certName, int keySize, String keyAlgorithm, int validYears) {
		this.validYears = validYears;
		initkeys(certName, keySize, keyAlgorithm);
	}

//	產Private、Public。
	private KeyPair getGenedKeyPair(String certName, int keySize, String keyAlgorithm) {
		KeyPairGenerator keyPairGen = null;
		try {
			keyPairGen = KeyPairGenerator.getInstance(keyAlgorithm);

			keyPairGen.initialize(keySize, new SecureRandom());

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return keyPairGen.genKeyPair();
	}

	private void initkeys(String certName, int keySize, String keyAlgorithm) {
		KeyPair keyPair = getGenedKeyPair(certName, keySize, keyAlgorithm);
		publicKey = (RSAPublicKey) keyPair.getPublic();
		privateKey = (RSAPrivateKey) keyPair.getPrivate();
	}

//	取KeyPair
	public String getEncodedKeyString(RSAKey rsaKey) {
		Encoder encode = Base64.getEncoder();
		return (rsaKey instanceof RSAPublicKey) ? encode.encodeToString(((RSAPublicKey) rsaKey).getEncoded())
				: encode.encodeToString(((RSAPrivateKey) rsaKey).getEncoded());
	}

	public byte[] getDecodedKeyBytes(String encodedKeyString) throws UnsupportedEncodingException {
		Decoder decode = Base64.getDecoder();

		return decode.decode(encodedKeyString);
	}

	public <T> Key recoverToKey(byte[] keyBytes, T keyType) throws InvalidKeySpecException {
		return (keyType instanceof PublicKey) ? keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes))
				: keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
	}

	public StringBuffer exportPublicEncodedString(String encodedString) {
		StringBuffer sbr = new StringBuffer();
		sbr.append("-----BEGIN CERTIFICATE-----\n");
		sbr.append(encodedString);
		sbr.append("-----END CERTIFICATE-----\n");
		return sbr;
	}

	public StringBuffer exportPrivateEncodedString(String encodedString) {
		StringBuffer sbr = new StringBuffer();
		sbr.append("-----BEGIN RSA PRIVATE KEY-----\n");
		sbr.append(encodedString);
		sbr.append("-----END RSA PRIVATE KEY-----\n");
		return sbr;
	}

	public Extensions extPathToGetExtensions(Path extFilePath) {
		ExtensionsGenerator extensionGen = new ExtensionsGenerator();
		Map<Object, List<String>> mp = convertStringToExtMap(extFilePath);
		extMapCheckAndConvertToExtension(mp).stream().forEach(extens -> extensionGen.addExtension(extens));
		return extensionGen.generate();
	}

	private Map<Object, List<String>> convertStringToExtMap(Path extFilePath) {
		Map<Object, List<String>> extMap = new HashMap<Object, List<String>>();
		try {
			Map<String, Object> extNameMap = getExtensionFieldNames();
			Files.readAllLines(extFilePath).stream().filter(perLine -> perLine.indexOf("=") != -1).filter(
					perLine -> extNameMap.containsKey(perLine.substring(0, perLine.indexOf('=')).toLowerCase().trim()))
					.forEach(extStr -> {
						String[] tmpArr = extStr.split("=");
						List<String> innerString = tmpArr[1].indexOf(",") != -1
								? Arrays.asList(tmpArr[1].replaceAll(" ", "").split(","))
								: Arrays.asList(tmpArr[1].trim());
						extMap.put(extNameMap.get(tmpArr[0].toLowerCase().trim()), innerString);
					});
		} catch (IOException | InstantiationException | IllegalAccessException | IllegalArgumentException
				| InvocationTargetException | NoSuchMethodException | SecurityException e) {
			e.printStackTrace();
		}
		return extMap;
	}

	private Map<String, Object> getExtensionFieldNames() throws InstantiationException, IllegalAccessException,
			IllegalArgumentException, InvocationTargetException, NoSuchMethodException, SecurityException, IOException {
		Map<String, Object> extNameMap = new HashMap<String, Object>();
		Extension extClass = Extension.class
				.getDeclaredConstructor(ASN1ObjectIdentifier.class, ASN1Boolean.class, ASN1OctetString.class)
				.newInstance(new ASN1ObjectIdentifier("2.5.29.9"), ASN1Boolean.TRUE, new DEROctetString("".getBytes()));
		Arrays.asList(Extension.class.getDeclaredFields()).stream().forEach(field -> {
			ReflectionUtils.makeAccessible(field);
			try {
				extNameMap.put(field.getName().toLowerCase(), field.get(extClass));
			} catch (IllegalArgumentException | IllegalAccessException e) {
				e.printStackTrace();
			}
		});
		return extNameMap;
	}

	@SuppressWarnings("rawtypes")
	private List<Extension> extMapCheckAndConvertToExtension(Map<Object, List<String>> extMap) {

		Function<Object[], Extension> newExtFunc = new Function<Object[], Extension>() {
			@Override
			public Extension apply(Object[] t) {
				DEROctetString t1 = null;
				try {
					t1 = new DEROctetString(new DERSequence((ASN1EncodableVector) t[1]).getEncoded());
				} catch (IOException e) {
					e.printStackTrace();
				}
				return new Extension((ASN1ObjectIdentifier) t[0], false, t1);
			}
		};

		@SuppressWarnings("unchecked")
		Function<Entry<Object, List<String>>, List<Extension>> funct = new Function() {
			@Override
			public Object apply(Object t) {
				Entry<Object, List<String>> obj = (Entry<Object, List<String>>) t;
				List<Extension> extList = new ArrayList<Extension>();
				ASN1EncodableVector vector = new ASN1EncodableVector();
				Object[] extObj = new Object[2];
				if (obj.getKey().equals(Extension.subjectAlternativeName)) {
					obj.getValue().forEach(innerStr -> {
						if (innerStr.matches("\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}")) {
							vector.add(new GeneralName(GeneralName.iPAddress, innerStr));
						} else {
							vector.add(new GeneralName(GeneralName.dNSName, innerStr));
						}
					});
					extObj[0] = Extension.subjectAlternativeName;
					extObj[1] = vector;
					extList.add(newExtFunc.apply(extObj));
				} else if (obj.getKey().equals(Extension.keyUsage)) {
					List<Integer> usageIntList = obj.getValue().stream().map(innerStr -> {
						return getKeyUsageValue(innerStr);
					}).collect(Collectors.toList());
					try {
						extList.add(new Extension(Extension.keyUsage, false,
								new DEROctetString(new KeyUsage(buildKeyUsageBits(usageIntList)))));
					} catch (IOException e) {
						e.printStackTrace();
					}
				} else if (obj.getKey().equals(Extension.basicConstraints)) {
					obj.getValue().forEach(innerStr -> {
						vector.add(new DEROctetString(innerStr.getBytes()));
					});
					extObj[0] = Extension.basicConstraints;
					extObj[1] = vector;
					extList.add(newExtFunc.apply(extObj));
				} else if (obj.getKey().equals(Extension.authorityKeyIdentifier)) {
					String authorityKeyValue = String.join(",", obj.getValue());
					AuthorityKeyIdentifier authKeyId = new AuthorityKeyIdentifier(authorityKeyValue.getBytes());
					try {
						extList.add(new Extension(Extension.authorityKeyIdentifier, false, authKeyId.getEncoded()));
					} catch (IOException e) {
						e.printStackTrace();
					}
				} else if (obj.getKey().equals(Extension.extendedKeyUsage)) {
					obj.getValue().forEach(innerStr -> {
						vector.add((KeyPurposeId) getFieldByObjClass(KeyPurposeId.id_kp_clientAuth, innerStr));
					});
					extObj[0] = Extension.extendedKeyUsage;
					extObj[1] = vector;
					extList.add(newExtFunc.apply(extObj));
				}
				return extList;
			}
		};

		return extMap.entrySet().stream().collect(() -> new ArrayList<Extension>(), (alist, ext) -> {
			alist.addAll(funct.apply(ext));
		}, (alist1, alist2) -> {
			alist1.addAll(alist2);
		});
	}

	private int getPowerCounted(int octInt) {
		int cnt = 0;
		while (octInt > 0) {
			octInt = octInt >> 1;
			cnt++;
		}
		return cnt;
	}

	private int buildKeyUsageBits(List<Integer> keyUsageList) {
		int keyUsageBits = 0;
		int keyUsage = -1;
		for (Integer kk : keyUsageList) {
			keyUsage = getPowerCounted(kk) - 1;
			switch (keyUsage) {
				case 7:
					keyUsageBits |= KeyUsage.digitalSignature;
					break;
				case 6:
					keyUsageBits |= KeyUsage.nonRepudiation;
					break;
				case 5:
					keyUsageBits |= KeyUsage.keyEncipherment;
					break;
				case 4:
					keyUsageBits |= KeyUsage.dataEncipherment;
					break;
				case 3:
					keyUsageBits |= KeyUsage.keyAgreement;
					break;
				case 2:
					keyUsageBits |= KeyUsage.keyCertSign;
					break;
				case 1:
					keyUsageBits |= KeyUsage.cRLSign;
					break;
				case 0:
					keyUsageBits |= KeyUsage.encipherOnly;
					break;
				case 15:
					keyUsageBits |= KeyUsage.decipherOnly;
					break;
				default:
					throw new IllegalArgumentException("Invalid key usage value: " + keyUsage);
			}
		}
		return keyUsageBits;
	}

	private int getKeyUsageValue(String keyUsageName) {
		int keyUsage = -1;
		try {
			KeyUsage keyUsageConstructor = KeyUsage
					.fromExtensions(new Extensions(new Extension(new ASN1ObjectIdentifier("2.5.29.9"), ASN1Boolean.TRUE,
							new DEROctetString("".getBytes()))));
			Field field = KeyUsage.class.getDeclaredField(keyUsageName);
			ReflectionUtils.makeAccessible(field);
			keyUsage = (int) field.get(keyUsageConstructor);
		} catch (IllegalAccessException | IllegalArgumentException | SecurityException | NoSuchFieldException e) {
			e.printStackTrace();
		}
		return keyUsage;
	}

	public X509Certificate issueCertificate(Path extFilePath) {
		return issueCertificate(publicKey, extFilePath, validYears);
	}

	private X509Certificate issueCertificate(PublicKey publicKey, Path extFilePath, int validYears) {
		X500Name x500NameIsser = ((X500NameBuilder) getX500NameBuider(ISSUER, ISSUER_VALUE).get(ISSUER)).build();
		X500Name x500NameSubject = ((X500NameBuilder) getX500NameBuider(SUBJ, SUBJECT_VALUE).get(SUBJ)).build();
		X509v3CertificateBuilder x509CertGen = new X509v3CertificateBuilder(x500NameIsser,
				BigInteger.valueOf(new SecureRandom().nextLong()), new Date(System.currentTimeMillis()),
				new Date(System.currentTimeMillis() + validRange * validYears), x500NameSubject,
				SubjectPublicKeyInfo.getInstance(((RSAPublicKey) publicKey).getEncoded()));

		Extensions exts = extPathToGetExtensions(extFilePath);

		Arrays.asList(exts.getExtensionOIDs()).forEach(oid -> {
			try {
				x509CertGen.addExtension(exts.getExtension(oid));
			} catch (CertIOException e) {
				e.printStackTrace();
			}
		});

		String keyAlgorithm = privateKey.getAlgorithm();
		String signatureAlgorithm = Strings.EMPTY;
		if (keyAlgorithm.equals("RSA")) {
			signatureAlgorithm = "SHA512withRSA";
		}
		X509Certificate x509Cert = null;
		try {
			ContentSigner sigGen = new JcaContentSignerBuilder(signatureAlgorithm).build(privateKey);
//			最後簽署憑證
			X509CertificateHolder x509CertHolder = x509CertGen.build(sigGen);
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			x509Cert = (X509Certificate) certFactory
					.generateCertificate(new ByteArrayInputStream(x509CertHolder.getEncoded()));
		} catch (OperatorCreationException | CertificateException | IOException e) {
			e.printStackTrace();
		}
		return x509Cert;
	}

	private Map<String, X500NameBuilder> getX500NameBuider(String identifierName, String x500SourceString) {

		Map<String, X500NameBuilder> x500NameBuildMap = new HashMap<String, X500NameBuilder>();

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

	private boolean valudResource(String resource) {
		return resource.contains("=") && resource.indexOf('=') != -1;
	}

	@SuppressWarnings("unchecked")
	private <T> Object getFieldByObjClass(Object classT, String fieldName) {
		Field[] fields = ((T) classT).getClass().getDeclaredFields();
		T field = null;
		try {
			for (Field fid : fields) {
				if (fid.getName().contains(fieldName)) {
					ReflectionUtils.makeAccessible(fid);
					field = (T) fid.get((T) classT);
				}
			}
		} catch (IllegalArgumentException | IllegalAccessException e) {
			e.printStackTrace();
		}
		return field;
	}
}
