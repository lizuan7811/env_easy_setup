package env_easy_setup;

import keyproduce.OkCertificate;

public class TestMain {
	
	public static void main(String[] args) throws Exception {
		OkCertificate okCertificate=new OkCertificate();
		
//		String aa="CN=123456789";
//		
//		System.out.println(aa.substring(0,aa.indexOf('=')));
//		System.out.println(aa.substring(aa.indexOf('=')+1,aa.length()));
//		System.out.println(aa);

		okCertificate.generateRootCA("test", 4096, "RSA");
//			keyProduce.genRSAP12("test",4096,"Admin@@@111");
//		okCertificate.trytryk();
	}

}
