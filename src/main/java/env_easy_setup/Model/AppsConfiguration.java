package env_easy_setup.Model;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Data;

@Data
@Configuration
@ConfigurationProperties(prefix="apps")
public class AppsConfiguration {
	
	private Docker docker;
	
	private Harbor harbor;
	
	private Kafka kafka;
	
	private Filebeat filebeat;
	
	private Elasticsearch elasticsearch;
	
	private Rke2 rke2;
	
	private Kibana kibana;
	
	private Boolean sysBeInited;
	
}
