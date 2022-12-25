package env_easy_setup;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;

@SpringBootApplication
@SpringBootConfiguration
public class ExecEasySetup {

	
	public static void main(String[] args) {
		SpringApplication sa=new SpringApplication(ExecEasySetup.class);
		
        ConfigurableApplicationContext cac=sa.run(args);
        Library cfu=cac.getBean(Library.class);
        cfu.printFields();
        cac.close();
	}

//	讀yaml
	
//	執行shell script 初始化系統。
	
/*	是否使用TLS加密連線，為True則產key
	建統一資料夾儲存(tls_dir)。
	elasticsearch
	kibana
	harbor-docker
	kafka、kafka-connector
	filebeat
		
*/	
	
	
}
