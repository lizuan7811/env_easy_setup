package env_easy_setup.Model;

import java.lang.reflect.Field;
import java.math.BigDecimal;
import java.util.Arrays;
import java.util.Objects;
import java.util.StringTokenizer;
import org.springframework.util.ReflectionUtils;
import lombok.Data;

@Data
public class CpuInfoBean {
	
	private CpuBean cpuBean;
	
	private CpuBean getCpuInstance() {
		return Objects.isNull(this.cpuBean)?new CpuBean():this.cpuBean;
	}
	
	public CpuInfoBean(StringTokenizer procStatFirstLine) {
		procStatFirstLine.nextToken();
		CpuBean cpuBean=getCpuInstance();
		
		Field[] fields=cpuBean.getClass().getDeclaredFields();
		
		Arrays.asList((Field[])fields).stream().forEach(field->{
			ReflectionUtils.makeAccessible((Field)field);
			try {
				((Field) field).set(cpuBean,procStatFirstLine.hasMoreTokens()?new BigDecimal(procStatFirstLine.nextToken()):BigDecimal.ZERO);
			} catch (IllegalArgumentException e) {
				e.printStackTrace();
			} catch (IllegalAccessException e) {
				e.printStackTrace();
			}
		});
		this.cpuBean=cpuBean;
//		for(Field field : fields) {
//			ReflectionUtils.makeAccessible(field);
//			field.set
//			field.set("",procStatFirstLine.hasMoreTokens()?new BigDecimal(procStatFirstLine.nextToken()):BigDecimal.ZERO);
//		}
	}
	public CpuBean getCpuBean() {
		return this.cpuBean;
	}
	public BigDecimal getCpuTotal() {
		return !Objects.isNull(cpuBean)?cpuBean.getUser().add(cpuBean.getGuest()).add(cpuBean.getGuest_nice()).add(cpuBean.getIdle()).add(cpuBean.getIowait()).add(cpuBean.getIrq()).add(cpuBean.getNice()).add(cpuBean.getSoftirq()).add(cpuBean.getStealstolen()).add(cpuBean.getSystem()):BigDecimal.ZERO;
	}
	
}
