/*
 * This Java source file was generated by the Gradle 'init' task.
 */
package env_easy_setup;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.text.StringSubstitutor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.core.io.support.ResourcePatternResolver;
import org.springframework.stereotype.Component;

import env_easy_setup.Model.KeyStringConfiguration;

@Component
public class InitUtils {
	@Autowired
	private AppsConfiguration appsConfiguration;
	@Autowired
	private KeyStringConfiguration keyStringEnumeration;

	/**
	 * 取config中設定key的參數取出作初始化
	 */
	private Map<String, String> getParams() {
		Map<String, String> paramsMap = new HashMap<String, String>();
		Field[] fields = KeyStringConfiguration.class.getDeclaredFields();

		Arrays.asList(fields).forEach(e -> {
			try {
				org.springframework.util.ReflectionUtils.makeAccessible(e);
				String tmpString = (String) e.get(keyStringEnumeration);
//				System.out.println(e.getName() + "\t" + tmpString);
				paramsMap.put(e.getName(), tmpString);
			} catch (IllegalArgumentException | IllegalAccessException e1) {
				e1.printStackTrace();
			}
		});
		return paramsMap;
	}

	/**
	 * 將模板key-init檔案做參數修改
	 */
	public void tempShellToKeyShell() {
		tempShellToKeyShell(getParams());
	}

	private void tempShellToKeyShell(Map<String, String> params) {
//		processTemplate("classpath:template_dir/template-key-init.sh", params);
		processTemplate("/config/template_dir/template-key-init.sh", params);

	}

	/**
	 * 渲染key shell模板
	 */
	private void processTemplate(String templatePath, Map<String, String> params) {
		StringSubstitutor stringSubstitutor = new StringSubstitutor(params);
		StringBuffer sb = new StringBuffer();
//		ResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();
//		Resource baseResour=resolver.getResource("classpath:");
		try {
//			String baseSourceDirURI=baseResour.getFile().getAbsolutePath();
//			String baseSourceDirURI = System.getProperty("user.dir");
//		Resource resour=resolver.getResource(templatePath);
			String basePathStr = EveryStepMethod.userDirPath;
			System.out.println(basePathStr);
			Paths.get(basePathStr,"/config/shell_dir/key-init.sh").toFile().delete();
//		try(BufferedReader br=Files.newBufferedReader(Paths.get(resour.getFile().getAbsolutePath()));
			try (BufferedReader br = Files.newBufferedReader(Paths.get(basePathStr + templatePath));
					BufferedWriter bw = Files.newBufferedWriter(
							Paths.get(basePathStr + "/config/shell_dir/key-init.sh"), StandardOpenOption.CREATE_NEW);) {
				br.lines().forEach(str -> {
					try {
						bw.write(stringSubstitutor.replace(str));
						bw.flush();
//					要在linux執行，需要使用\n，window換行需要\r\n
						bw.write('\n');
					} catch (IOException e) {
						e.printStackTrace();
					}
				});
			} catch (IOException e1) {
				e1.printStackTrace();
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			System.out.println("結束!");
		}
	}

}
