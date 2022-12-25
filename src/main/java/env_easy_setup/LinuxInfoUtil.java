//package env_easy_setup;
//
//import java.io.BufferedReader;
//import java.io.IOException;
//import java.io.InputStreamReader;
//import java.lang.management.ManagementFactory;
//import java.math.BigDecimal;
//import java.math.RoundingMode;
//import java.nio.charset.StandardCharsets;
//import java.nio.file.Files;
//import java.nio.file.Paths;
//import java.util.StringTokenizer;
//
//import com.sun.management.OperatingSystemMXBean;
//
//import env_easy_setup.Model.CpuInfoBean;
//
//public class LinuxInfoUtil {
////	private static final String CPU_FILE="/proc/stat";
//
//	private static final String CPU_FILE="/";
//	private static final String LOAD_COMMAND="update";
//	public static BigDecimal getCpuInfo() {
//		try {
//			BufferedReader br=Files.newBufferedReader(Paths.get(CPU_FILE), StandardCharsets.UTF_8);
//			StringTokenizer procStatFirstLine=new StringTokenizer(br.readLine());
//			CpuInfoBean cpuInfoBean=new CpuInfoBean(procStatFirstLine);
//			BigDecimal total=cpuInfoBean.getCpuTotal();
//			Thread.sleep(1000);
//			br=Files.newBufferedReader(Paths.get(CPU_FILE), StandardCharsets.UTF_8);
//			procStatFirstLine=new StringTokenizer(br.readLine());
//			CpuInfoBean cpuInfoBean1=new CpuInfoBean(procStatFirstLine);
//			BigDecimal total1=cpuInfoBean1.getCpuTotal();
//			BigDecimal totalResult=total1.subtract(total);
//			BigDecimal idle=cpuInfoBean1.getCpuBean().getIdle();
//			BigDecimal pcpu=new BigDecimal(100).multiply(totalResult.subtract(idle)).divide(totalResult,0,RoundingMode.HALF_UP);
//			br.close();
//			return pcpu;
//		}catch(IOException | InterruptedException ioe) {
//			ioe.printStackTrace();
//			return new BigDecimal(0);
//		}
//	}
//	
//	public static BigDecimal getTotalMemory() {
//		OperatingSystemMXBean osmxb= (OperatingSystemMXBean)ManagementFactory.getOperatingSystemMXBean();
//		return new BigDecimal(osmxb.getTotalMemorySize());
//	}
//	
//	public static BigDecimal getAvailableMemory() {
//		OperatingSystemMXBean osmxb= (OperatingSystemMXBean)ManagementFactory.getOperatingSystemMXBean();
//		BigDecimal total=new BigDecimal(osmxb.getTotalMemorySize());
//		BigDecimal free=new BigDecimal(osmxb.getFreeMemorySize());
//		BigDecimal pmem=new BigDecimal(100).multiply(total.subtract(free)).divide(total,0,RoundingMode.HALF_UP);
//		return pmem;
//	}
//	
//	public static BigDecimal getLoad() {
//		try {
//			Runtime runtime=Runtime.getRuntime();
//			BigDecimal cpuPerformance=new BigDecimal(0.7).multiply(new BigDecimal(runtime.availableProcessors()));
//			Process process=runtime.exec(LOAD_COMMAND);
//			BufferedReader br=new BufferedReader(new InputStreamReader(process.getInputStream()));
//			String topLoad=br.readLine();
//			BigDecimal load=new BigDecimal(topLoad.substring(topLoad.lastIndexOf(" ")+1));
//			BigDecimal pload=new BigDecimal(100).multiply(load).divide(cpuPerformance,0,RoundingMode.HALF_UP);
//			br.close();
//			process.destroy();
//			return pload;
//		}catch(Exception e) {
//			e.printStackTrace();
//			return new BigDecimal(0);
//		}
//	}
//}
