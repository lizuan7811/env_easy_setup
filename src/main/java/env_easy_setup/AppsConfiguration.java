package env_easy_setup;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import env_easy_setup.Model.Docker;
import env_easy_setup.Model.Elasticsearch;
import env_easy_setup.Model.Filebeat;
import env_easy_setup.Model.Harbor;
import env_easy_setup.Model.Kafka;
import env_easy_setup.Model.Kibana;
import env_easy_setup.Model.Rancher;
import env_easy_setup.Model.Rke2;
import env_easy_setup.Model.Sysinfo;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Configuration
@ConfigurationProperties(prefix="apps")
@NoArgsConstructor
@AllArgsConstructor
public class AppsConfiguration {

	private Sysinfo sysinfo;
	
	private Docker docker;
	
	private Harbor harbor;

	private Rke2 rke2;
	
	private Rancher rancher;
	
	private Kafka kafka;
	
	private Elasticsearch elasticsearch;

	private Kibana kibana;

	private Filebeat filebeat;
//	@Bean
//	public AppsConfiguration newInstance() {
//		return new AppsConfiguration(sysEnvInit,docker,harbor,rke2,rancher,kafka,elasticsearch,kibana,filebeat);
//	}
}
