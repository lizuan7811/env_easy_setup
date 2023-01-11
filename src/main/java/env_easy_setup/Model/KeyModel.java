package env_easy_setup.Model;

import lombok.Data;

@Data
public class KeyModel {

	private String name;
	
	private String type;
	
	private String caName;
	
	private String serverName;
	
	private String clientName;

	private String storeName;
	
	private String validityDay;
	
	private String subject;
	
/*
 * name: elasticsearch
        type: PKCS12
        ca-name: elasticsearch-ca
        server-name: elasticsearch-server
        client-name: elasticsearch-client
        store-name: elasticsearch
        validity-day: 3650
        subject:
 */
	
}
