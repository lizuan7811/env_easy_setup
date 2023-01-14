package env_easy_setup.Model;

import com.fasterxml.jackson.databind.ser.impl.IteratorSerializer;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import env_easy_setup.AppsConfiguration;



@Configuration
public enum KeyStringEnumeration {
	
	HARBOR_CA_NAME("keyStringValue"),
	HARBOR_SUBJ(""),
	HARBOR_SERVER(""),
	VALIDITY_DAY(""),
	V3_FILE_NAME(""),
	KAFKA_CA_NAME(""),
	KAFKA_SUBJ(""),
	KAFKA_STORE_NAME(""),
	KAFKA_TRUSTSTORE_ALIAS(""),
	KAFKA_KEYTSTORE_ALIAS(""),
	DNS_NAME(""),
	KAFKA_KEYSTORE_ALIAS("");

	private String keyStringValue;
	KeyStringEnumeration(String keyStringValue) {
		this.keyStringValue=keyStringValue;
	}
	
	public KeyStringEnumeration getKeyEnum(String keyEnumValue) {
		KeyStringEnumeration resultKeyStringEnumeration = null;
		for(KeyStringEnumeration inKeyEnum: KeyStringEnumeration.values()) {
			if (inKeyEnum.getKeyStringValue().equals(keyEnumValue)){
				resultKeyStringEnumeration= inKeyEnum;
				break;
			}
		}
		return resultKeyStringEnumeration;
	}

	public String getKeyStringValue() {
		return this.keyStringValue;
	}
	
}
