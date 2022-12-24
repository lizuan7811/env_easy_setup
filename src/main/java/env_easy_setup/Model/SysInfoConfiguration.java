package env_easy_setup.Model;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Data;

@Data
@Configuration
@ConfigurationProperties(prefix="sys-info")
public class SysInfoConfiguration {

	private String path;
	
	private String os;
	
	private String memory;
	
	private String storage;
	
}
