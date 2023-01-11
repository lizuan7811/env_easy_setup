package env_easy_setup;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.lang.reflect.Field;
import java.math.BigDecimal;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.text.StringSubstitutor;
import org.apache.tika.utils.StreamGobbler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.core.io.support.ResourcePatternResolver;
import org.springframework.stereotype.Component;
import org.springframework.util.ReflectionUtils;
import org.springframework.util.ResourceUtils;

import ch.qos.logback.core.util.FileUtil;
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
@Configuration
public class EveryStepMethod {
	private final AppsConfiguration appsConfiguration;

	@Autowired
	public EveryStepMethod(AppsConfiguration appsConfiguration) {
		this.appsConfiguration = appsConfiguration;
	}

	private List<String> selectedItems;

	private BigDecimal cpu;

	private BigDecimal availableMem;

	private String[] items;

	private String[] existItems;

	private Map<String, String> itemsPathMap;

	/**
	 * 開始安裝程式
	 */
	public void startSetup() {
		if (initSysInfo()) {
			execShellScript(this.selectedItems);
		}
	}

	/**
	 * 初始化系統資訊
	 */
	public boolean initSysInfo() {
//		CPU、記憶體量、JAVA版本、查系統是否安裝過選擇的項目
//		this.cpu = LinuxInfoUtil.getCpuInfo();
//		this.availableMem = LinuxInfoUtil.getAvailableMemory();
//		蒐集選擇為true的項目
		this.selectedItems = getSelectedItems();
//		根據蒐集到為true的項目去執行讀取shell script，確認檔案是否存在。
//			boolean isExist=validFileExist(selectedItems);
//			若檔案均存在>繼續執行，否則需要建立相對應的檔案。
		return validFileExist(selectedItems);
	}

	/**
	 * 取得選擇的項目List
	 * 
	 * @return
	 */
	private List<String> getSelectedItems() {
		List<String> selectedItemsList = new ArrayList<String>();
		Field[] fields = AppsConfiguration.class.getDeclaredFields();

		for (Field field : fields) {
			ReflectionUtils.makeAccessible((Field) field);
			try {
				if (((IBaseConfig) (field).get(appsConfiguration)).getSelect()) {
					selectedItemsList.add(((Field) field).getName());
				}
			} catch (IllegalArgumentException | IllegalAccessException e) {
				e.printStackTrace();
			}
		}
		return selectedItemsList;
	}

	/**
	 * 檢查選擇的項目shell script檔案存在，印出不存在的檔案
	 * 
	 * @param selectedItemsList
	 * @return
	 * @throws IOException
	 */
	private boolean validFileExist(List<String> selectedItemsList) {
		List<String> copiedItemsList = selectedItemsList;
		itemsPathMap=new HashMap<String,String>();
		try {
			ResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();
			Resource resour=resolver.getResource("classpath:shell_dir/");
			Path paths=Paths.get(resour.getURI());
			
//			Path paths=Paths.get("./config/shell_dir/");
			
			Stream<Path> fileStream = Files.list(paths.toAbsolutePath());
			
			fileStream.forEach(path -> {
				String fileName = path.toFile().getName();
//				String fileAbsolutePath=path.toFile().getAbsolutePath();
				String cutedFileName = fileName.substring(0, fileName.indexOf('-'));
				
				if (copiedItemsList.contains(cutedFileName)) {
					itemsPathMap.put(cutedFileName, path.toString());
					copiedItemsList.remove(cutedFileName);
				}
//				setAndStartShell(fileAbsolutePath);
			});
			fileStream.close();

//		迭代查看是否找到不存在的檔案並印出
			copiedItemsList.stream().forEach(opt -> {
				System.out.println("#*********File is not Exist**********#");
				Optional.ofNullable(opt).ifPresent(new Consumer<String>() {
					@Override
					public void accept(String t) {
						System.out.println(t);
					}
				});
				System.out.println("#************************************#");
			});
		} catch (IOException  e) {
			e.printStackTrace();
		}
		return copiedItemsList.isEmpty();
	}

	
	private void buildKeyInitFile() {
		
//		讀template
//		讀config
//		渲染Template
		BufferedReader bReader=new BufferedReader(new InputStreamReader(null));
		BufferedWriter bWriter=new BufferedWriter(new OutputStreamWriter(null));
		
		
		
		
		
	}
	
	
	private static void tempToKeyShell(Map<String,String> params) {
		
		processTemplate("classpath:template_dir/template-key.sh",params);
	}
	
	/**
	 * 渲染模板
	 */
	private static void processTemplate(String templatePath,Map<String,String> params) {
		
		StringSubstitutor stringSubstitutor=new StringSubstitutor(params);
		StringBuffer sb=new StringBuffer();
		ResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();
		Resource resour=resolver.getResource(templatePath);
		
		try(BufferedReader br=Files.newBufferedReader(Paths.get(resour.getFile().getAbsolutePath()));
			BufferedWriter bw=Files.newBufferedWriter(Paths.get(""));){
			
			br.lines().forEach(str->{
				try {
					bw.write(stringSubstitutor.replace(templatePath));
				} catch (IOException e) {
					e.printStackTrace();
				}
			});
			
		}catch(Exception e){
			
			
		}
		finally {
			
		}
		
		
		 
	}
	
	
	/**
	 * 執行蒐集到的Shell Sript
	 */
	private void execShellScript(List<String> selectedItems) {
		System.out.println(">>>>>>start execShellScript!");

//		根據list中的項目執行相對應的shell script。
		assert (itemsPathMap.size() > 0);
		
//		selectedItems.stream().filter(shell->shell.)
		setup(new IBaseConfig() {
			@Override
			public Boolean getSelect() {
				// TODO Auto-generated method stub
				return null;
			}
		});
//		初始化系統
//		安裝Docker指令
//		安裝RKE2指令
	}

	private void setup(IBaseConfig ibaseConfig) {
		
		

	}

	/**
	 * 設定shell script檔案的執行權限
	 */
	private void setAndStartShell(String abPath) {
		try {
//			Linux's cmd behind:
//			ProcessBuilder processBuild = new ProcessBuilder("chmod", "+x ",abPath);
			ProcessBuilder processBuild = new ProcessBuilder("cat", abPath);
//			Windows's cmd behind:
//			ProcessBuilder processBuild = new ProcessBuilder("cmd","/C","more", abPath);
			
			Process process = processBuild.start();
			process.waitFor();
			printResult(process);
		} catch (IOException | InterruptedException e) {
			e.printStackTrace();
		}
	}


	/**
	 * 執行Shell Script
	 */
	private void processBuilder(Path shellPath) {
		try {
			ProcessBuilder processBuild = new ProcessBuilder(String.format("./%s", shellPath.toFile().getName()));
			Process process = processBuild.start();
			process.waitFor();
			printResult(process);

		} catch (IOException | InterruptedException e) {
			e.printStackTrace();
		}
	}

	private void printResult(Process process) {
		try (Stream<String> brSuccess = new BufferedReader(new InputStreamReader(process.getInputStream(), "UTF-8")).lines();
				Stream<String> brError = new BufferedReader(new InputStreamReader(process.getErrorStream(), "UTF-8")).lines();) {
//			List<String> brSuccess=new BufferedReader(new InputStreamReader(process.getInputStream(),"UTF-8")).lines().collect(Collectors.toList());
//			List<String> brError=new BufferedReader(new InputStreamReader(process.getErrorStream(),"UTF-8")).lines().collect(Collectors.toList());
			brSuccess.forEach(System.out::println);
			brError.forEach(System.out::println);
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}
	}

}
