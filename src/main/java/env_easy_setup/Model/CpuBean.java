package env_easy_setup.Model;

import java.math.BigDecimal;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
@Data
@NoArgsConstructor
@AllArgsConstructor
public class CpuBean {
	private BigDecimal user,nice,system,idle,iowait,irq,softirq,stealstolen,guest,guest_nice;

}
