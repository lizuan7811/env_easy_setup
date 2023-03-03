package env_easy_setup;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.math.BigDecimal;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Stream;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.ReflectionUtils;

import env_easy_setup.Model.TlsConfig;
import lombok.Data;
import shellutils.ShellUtils;
@Data
@Configuration
public class EveryStepMethod {
	private final AppsConfiguration appsConfiguration;

	private final TlsConfig tlsConfig;
	
	private final InitUtils initUtils;
	
	private List<String> errorCollectList=new ArrayList<String>();
	
	@Autowired
	public EveryStepMethod(AppsConfiguration appsConfiguration,TlsConfig tlsConfig,InitUtils initUtils) {
		this.appsConfiguration = appsConfiguration;
		this.tlsConfig=tlsConfig;
		this.initUtils=initUtils;
	}

	private List<String> selectedItems=new ArrayList<String>();

	private BigDecimal cpu;

	private BigDecimal availableMem;

	private String[] items;

	private String[] existItems;

	private Map<String, String> itemsPathMap;

	public final static String userDirPath=Paths.get(System.getProperty("user.dir"),"src/main/resources/").toString();
	
	/**
	 * 開始安裝程式
	 */
	public void startSetup() {
		
//		初始化sys前，先確認是否使用tls
		if(tlsConfig.getEncryptConn()) {
			this.selectedItems.add("key");
		}
		
//		初始化系統參數並開啟防火牆。
		
//		根據蒐集到為true的項目去執行讀取shell script，確認檔案是否存在，檔案均存在>繼續執行，否則需要建立相對應的檔案。
		if (initSysInfo() ) {
			System.out.printf("Start to execute shells!");
			assert (itemsPathMap.size() > 0);
			
			this.selectedItems.stream().forEach(selectItemStr->{
//				執行shell
					System.out.printf(">>> %s: %s\n","執行",selectItemStr);
					System.out.println(ShellUtils.execShell(selectItemStr));

			});
			System.out.printf("Finished execute shells!");
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
		this.selectedItems.addAll(getSelectedItems());
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
//		渲染產生key的模板
		if(tlsConfig.getEncryptConn()) {
			initUtils.tempShellToKeyShell();
		}
		
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
	 * 檢查選擇的項目shell script檔案存在，同時設定檔案可執行權限，印出不存在的檔案
	 * 
	 * @param selectedItemsList
	 * @return
	 * @throws IOException
	 */
	private boolean validFileExist(List<String> selectedItemsList) {
		List<String> copiedItemsList = new ArrayList<String>(selectedItemsList);
		
		itemsPathMap=new HashMap<String,String>();
		try {
//			ResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();
//			Resource resour=resolver.getResource("classpath:shell_dir/");
//			Path paths=Paths.get(resour.getURI());
			
			Path paths=Paths.get(userDirPath+"/config/shell_dir/");
			Stream<Path> fileStream = Files.list(paths.toAbsolutePath());
			fileStream.forEach(path -> {

				String fileName = path.toFile().getName();
				String fileAbsolutePath=path.toFile().getAbsolutePath();
				String cutedFileName = fileName.indexOf("-")!=-1?fileName.substring(0, fileName.indexOf('-')):fileName;
				if (copiedItemsList.contains((String)cutedFileName)) {
//					*-*.sh
					itemsPathMap.put(cutedFileName, path.toString());
					copiedItemsList.remove(cutedFileName);
				}
//				setShellFileAuth(Arrays.asList("chmod","+x",fileAbsolutePath));
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

//	private boolean validElementEffect(List<String>copiedItemsList) {
//		
////		docker + harbor
////		k3s+rancher
////		kibana+elasticsearch
//		
//		
//		return false;
//	}
//	private void buildKeyInitFile() {
//		
//		BufferedReader bReader=new BufferedReader(new InputStreamReader(null));
//		BufferedWriter bWriter=new BufferedWriter(new OutputStreamWriter(null));
//		
//	}
	
	/**
	 * 執行蒐集到的Shell Sript
	 */
	private void execShellScript(String element) {
//		element為初始化蒐集到的需要執行的項目，依順序執行。
		System.out.printf("Execute %s shell!\n",element);
		this.<String>workShell(element,new Consumer<String>() {
			@Override
			public void accept(String consumeElement) {
				processBuilder(itemsPathMap.get(consumeElement));
			}
		});
	}

	private <T>void workShell(String element,Consumer<T> consumeElement) {
//		可以在這裡針對不同的檔案做不同的處理。
		
		consumeElement.accept((T)element);
	}

	/**
	 * 設定選擇的 shell檔案執行權限
	 */
	private void setShellFileAuth(List<String> commandList) {
		try {
//			Linux's cmd behind: chmod +x ${file}
			ProcessBuilder processBuild = new ProcessBuilder();
			processBuild.command(commandList);
			Process chmodProcess = processBuild.start();
			chmodProcess.waitFor();
			printResult(chmodProcess);
		} catch (IOException | InterruptedException e) {
			e.printStackTrace();
		}
	}


	/**
	 * 執行單個Shell Script
	 */
	private void processBuilder(String shellPath) {
		try {
			System.out.println("執行:\t"+shellPath);
			ProcessBuilder processBuild = new ProcessBuilder(shellPath);
			Process process = processBuild.start();
			int processResult=process.waitFor();
			System.out.println(processResult);
			printResult(process);
		} catch (IOException | InterruptedException e) {
			e.printStackTrace();
		}
	}

	/**
	 * 列印執行shell的結果
	 */
	private void printResult(Process process) {
		try (Stream<String> brSuccess = new BufferedReader(new InputStreamReader(process.getInputStream(), "UTF-8")).lines();
				Stream<String> brError = new BufferedReader(new InputStreamReader(process.getErrorStream(), "UTF-8")).lines();) {
			if(Objects.nonNull(brSuccess)) {
				System.out.println(">>> Execute shell : Successed!");
				brSuccess.forEach(System.out::println);
			}
			if(Objects.nonNull(brSuccess)) {
				System.out.println(">>> Execute shell : Error!");
				brError.forEach(System.out::println);
			}
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}
	}
}
