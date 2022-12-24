package env_easy_setup.Model;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Data;

@Data
@Configuration
@ConfigurationProperties(prefix="tls-config")
public class TlsConfig {

	private String encryptConn;
	
	private List<KeyModel> keyModel;
	
}
