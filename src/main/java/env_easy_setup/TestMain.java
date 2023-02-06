package env_easy_setup;

import keyproduce.KeyProduce;
import keyproduce.OkCertificate;

public class TestMain {
	
	public static void main(String[] args) {
		
		OkCertificate keyProduce=new OkCertificate();
//		keyProduce.generateRootCA("test", 4096, "RSA");
		keyProduce.genRSAP12("test", 256,"Admin@@@111");
	}

}
