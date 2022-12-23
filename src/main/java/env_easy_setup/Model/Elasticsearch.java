package env_easy_setup.Model;

import org.springframework.context.annotation.Configuration;

import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = false)
@Configuration
public class Elasticsearch {
	
	private String version;
	
	private Boolean select;
}
