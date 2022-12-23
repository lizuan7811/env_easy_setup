package env_easy_setup.Model;

import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;
import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = false)
@Configuration
public class Docker {
	
	private String version;
	
	private Boolean select;

}
