package env_easy_setup.Model;

import org.springframework.context.annotation.Configuration;

import env_easy_setup.IBaseConfig;
import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = false)
@Configuration
public class Elasticsearch  implements IBaseConfig{
	
	private String version;
	
	private Boolean select;
}
