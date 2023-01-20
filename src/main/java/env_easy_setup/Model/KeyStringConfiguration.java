package env_easy_setup.Model;

import java.util.List;

import com.fasterxml.jackson.databind.ser.impl.IteratorSerializer;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import env_easy_setup.AppsConfiguration;
import lombok.Data;


@Data
@Configuration
public class KeyStringConfiguration {
	
	@Value("${tls-config.key-model[2].ca-name}")
	private String HARBOR_CA_NAME;
	@Value("${tls-config.key-model[2].subject}")
	private String  HARBOR_SUBJ;
	@Value("${tls-config.key-model[2].server-name}")
	private String HARBOR_SERVER;
	@Value("${tls-config.key-model[0].validity-day}")
	private String VALIDITY_DAY;
	@Value("${tls-config.key-model[3].ca-name}")
	private String KAFKA_CA_NAME;
	@Value("${tls-config.key-model[3].subject}")
	private String KAFKA_SUBJ;
	@Value("${tls-config.key-model[3].store-name}")
	private String KAFKA_STORE_NAME;
	@Value("${tls-config.key-model[3].alias}")
	private String KAFKA_TRUSTSTORE_ALIAS;
	@Value("${tls-config.key-model[3].alias}")
	private String KAFKA_KEYSTORE_ALIAS;
	@Value("${tls-config.v3-filename}")
	private String V3_FILE_NAME;
	@Value("${tls-config.dns-name}")
	private String DNS_NAME;
	
}
