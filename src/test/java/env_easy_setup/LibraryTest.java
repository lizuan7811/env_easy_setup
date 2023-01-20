package env_easy_setup;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(classes=InitUtils.class)
public class LibraryTest {
	@Autowired
	private AppsConfiguration appsConfiguration;
	@Test
    public void printFields() {
    	
    	System.out.println(appsConfiguration.getDocker().getVersion());

    	System.out.println(appsConfiguration.getElasticsearch().getVersion());

    	System.out.println(appsConfiguration.getFilebeat().getVersion());
    	
    	System.out.println(appsConfiguration.getHarbor().getVersion());

    	
    }
}
