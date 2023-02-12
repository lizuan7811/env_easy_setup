package env_easy_setup;

import keyproduce.OkCertificate;

public class TestMain {
	
	public static void main(String[] args) throws Exception {
		OkCertificate okCertificate=new OkCertificate();
		okCertificate.generateRootCA("test", 4096, "RSA");
//			keyProduce.genRSAP12("test",4096,"Admin@@@111");
//		okCertificate.trytryk();
	}

}
