package env_easy_setup;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.apache.commons.io.IOUtils;

public class TLSKeyProduce {
	
	public static void main(String[] args) throws Exception{
//		CertificateFactory cf=CertificateFactory.getInstance("X.509");
//		FileInputStream in=new FileInputStream("path to server certificate.pem");
		KeyStore trustStore = KeyStore.getInstance("JKS");
		trustStore.load(null);		
		try {
//			X509Certificate cacert=(X509Certificate)cf.generateCertificate(null);
//			trustStore.setCertificateEntry("server_alias",cacert);
			
		}finally {
			System.out.println("Finally");
//			IOUtils.closeQuietly(in);
		}
		TrustManagerFactory tmf=TrustManagerFactory.getInstance("TLS");
		tmf.init(trustStore);
		
		SSLContext sslContext=SSLContext.getInstance("TLS");
		sslContext.init(null, tmf.getTrustManagers(),new SecureRandom());
		
//		return sslContext;
	}
	

}
