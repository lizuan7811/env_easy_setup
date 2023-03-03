package shellutils;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.apache.commons.lang3.StringUtils;

import io.kubernetes.client.util.Strings;

//
////sysinfo-init.sh 初始化系統 執行
//sysInfoShell();
////firewallcmd-init.sh 防火牆設定
//firewallCmdShell();
////docker-init.sh 安裝
//dockerShell();
////harbor-init.sh 安裝
//harborShell();
////rke2-init.sh 安裝rke2
//rke2InitShell();
////rancher-init.sh 安裝k3s+rancher
////kafka-init.sh 安裝kafka
//kafkaInitShell();
////filebeat-init.sh 安裝
//fileBeatInitShell();
////elasticsearch-init.sh 安裝
////kibana.sh 安裝
////execShellScript(obj);
public class ShellUtils {
	private static Map<String, Function<String, String>> funcsMap;

	static {
		funcsMap = new HashMap<String, Function<String, String>>();
		initFuncsMap();
	}

	public static String execShell(String selectItemStr) {

		String result = StringUtils.EMPTY;
		if (funcsMap.containsKey(selectItemStr)) {
			result = funcsMap.get(selectItemStr).apply(selectItemStr);
		}
		return result;
	}

	public static void initFuncsMap() {
		funcsMap.put("key", keyInitShell());
// sysinfo有開啟防火牆設定。
		funcsMap.put("sysinfo", sysInfoShell());

		funcsMap.put("docker", dockerShell());

		funcsMap.put("harbor", harborShell());

		funcsMap.put("rke2", rke2InitShell());

		funcsMap.put("kafka", kafkaInitShell());

		funcsMap.put("filebeat", fileBeatInitShell());

		funcsMap.put("elasticsearch", elasticsearchShell());

		funcsMap.put("kibana", kibanaShell());
	}

	private static Function<String, String> keyInitShell() {
		return new Function<String, String>() {
			@Override
			public String apply(String t) {

				System.out.println(t);

				return t;
			}
		};
	}

	private static Function<String, String> sysInfoShell() {
		return new Function<String, String>() {
			@Override
			public String apply(String t) {

				System.out.println(t);

				return t;
			}
		};
	}

	private static Function<String, String> dockerShell() {
		return new Function<String, String>() {
			@Override
			public String apply(String t) {
				System.out.println(t);

				return t;
			}
		};
	}

	private static Function<String, String> harborShell() {
		return new Function<String, String>() {
			@Override
			public String apply(String t) {
				System.out.println(t);

				return t;
			}
		};
	}

	private static Function<String, String> rke2InitShell() {
		return new Function<String, String>() {
			@Override
			public String apply(String t) {
				System.out.println(t);

				return t;
			}
		};
	}

	private static Function<String, String> kafkaInitShell() {
		return new Function<String, String>() {
			@Override
			public String apply(String t) {
				System.out.println(t);

				return t;
			}
		};
	}

	private static Function<String, String> fileBeatInitShell() {
		return new Function<String, String>() {
			@Override
			public String apply(String t) {
				System.out.println(t);

				return t;
			}
		};
	}

	private static Function<String, String> elasticsearchShell() {
		return new Function<String, String>() {
			@Override
			public String apply(String t) {

				return t;
			}
		};
	}

	private static Function<String, String> kibanaShell() {
		return new Function<String, String>() {
			@Override
			public String apply(String t) {
				System.out.println(t);

				return t;
			}
		};
	}

}
