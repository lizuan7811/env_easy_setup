package env_easy_setup;

import java.lang.reflect.Field;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

import org.assertj.core.util.Arrays;
import org.springframework.beans.factory.annotation.Autowired;

import env_easy_setup.Model.AppsConfiguration;
import lombok.Data;
//讀取要執行的資料

//將必要安裝的參數先蒐集起來。

//檢查資料是否存在

//初始化

//Docker

//Harbor

//RKE2

//Rancher

//KAFKA
@Data
public class EveryStepMethod {
	
	private final AppsConfiguration appsConfiguration;
	
	@Autowired
	public EveryStepMethod(AppsConfiguration appsConfiguration) {
		this.appsConfiguration=appsConfiguration;
	}
	
	private BigDecimal cpu;
	
	private BigDecimal availableMem;
	
	private String[] items;
	
	private String[] existItems;


	public void initSysInfo() {
//		CPU、記憶體量、JAVA版本、查系統是否安裝過選擇的項目
		this.cpu=LinuxInfoUtil.getCpuInfo();
		this.availableMem=LinuxInfoUtil.getAvailableMemory();
//		蒐集選擇為true的項目
		List<String> selectedItems=getSelectedItems();
		
		
		
		
		
	}
	
	/**
	 * 取得選擇的項目List
	 * @return
	 */
	private List<String> getSelectedItems(){
		List<String> selectedItemsList=new ArrayList<String>();
		
		Field[] fields=appsConfiguration.getClass().getDeclaredFields();
		
		Arrays.asList(fields).stream().filter(field->((Field) field).getAnnotatedType() instanceof IBaseConfig).forEach(field->{
			Boolean tag;
			try {
				tag = ((IBaseConfig)((Field) field).get(this.appsConfiguration)).getSelect();
				if(tag.equals(true)) {
					selectedItemsList.add(((Field) field).getName());
				}
			} catch (IllegalArgumentException | IllegalAccessException e) {
				e.printStackTrace();
			}
		});
		return selectedItemsList;
	}
	
	
}
