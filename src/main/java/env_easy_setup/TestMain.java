package env_easy_setup;

import java.nio.file.Path;
import java.nio.file.Paths;
import keyproduce.KeyUtils;

public class TestMain {
	public static void main(String[] args) throws Exception {
		KeyUtils keyUtils = new KeyUtils("test", 4096, "RSA", 10);
		Path extFilePath = Paths
				.get("C:/Users/ASUS/eclipse-workspace/env_easy_setup/src/main/resources/shell_dir/v3.ext");
		System.out.println(keyUtils.issueCertificate(extFilePath));
	}

}
