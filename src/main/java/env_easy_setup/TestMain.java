package env_easy_setup;

import java.nio.file.Paths;

import keyproduce.KeyUtils;
import keyproduce.OkCertificate;

public class TestMain {
	
	public static void main(String[] args) throws Exception {
//		OkCertificate okCertificate=new OkCertificate();
		KeyUtils keyUtils=new KeyUtils();
//		String aa="CN=123456789";
//		
//		System.out.println(aa.substring(0,aa.indexOf('=')));
//		System.out.println(aa.substring(aa.indexOf('=')+1,aa.length()));
//		System.out.println(aa);
		
		keyUtils.convertStringToExtMap(Paths.get("C:/Users/ASUS/eclipse-workspace/env_easy_setup/src/main/resources/shell_dir/v3.ext"));

//		okCertificate.generateRootCA("test", 4096, "RSA");
//			keyProduce.genRSAP12("test",4096,"Admin@@@111");
//		okCertificate.trytryk();
	}

}
