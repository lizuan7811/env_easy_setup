#!/bin/bash
#安裝環境初始化

##初始化系統時間
#開啟ntp
timedatectl set-ntp yes
#設定時區
timedatectl set-timezone Asia/Taipei
#顯示設定狀態
timedatectl show

##關閉swap
#暫時關閉
swapoff -a
#永遠關閉，或可打開/etc/fstab，註解swap那一行
sed -i 's/.*swap.*/#&/' /etc/fstab

##因Firewalld 与 RKE2 的默认 Canal（Calico + Flannel）會產生衝突，需在安裝RKE2的系統將NetworkManager 設定為忽略 calico/flannel port。
#在/etc/NetworkManager/conf.d中创建一个名为rke2-canal.conf的配置文件，其内容如下：Networkmanager

cat > /etc/NetworkManager/conf.d/rke2-canal.conf << EOF
[keyfile]
unmanaged-devices=interface-name:cali*;interface-name:flannel*
EOF

#重新reload NetworkManager.service
systemctl reload NetworkManager.service



#網路傳輸設定
cat > /etc/sysctl.conf << EOF
net.bridge.bridge-nf-call-ip6tables=1
net.bridge.bridge-nf-call-iptables=1
net.ipv4.ip_forward=1
EOF

##讓設定生效
modprobe br_netfilter
sysctl -p /etc/sysctl.conf
sysctl –system


echo '設定防火牆規則，開啟防火牆port:'
tcpports=(80 443 6443 10250 22 2376 9345 2379 2380 30000-32767 5473 9099 10254 8080 8443 9092 9093 5601 9200 8110)
udpports=( 6081 8472 30000-32767)

for pt in "${tcpports[@]}"; do
firewall-cmd --zone=public --permanent --add-port=$pt/tcp
done

for pt in "${udpports[@]}"; do
firewall-cmd --zone=public --permanent --add-port=$pt/udp
done
echo 'healthcheck related permits:'
sudo firewall-cmd --add-port=4240/tcp --permanent
sudo firewall-cmd --remove-icmp-block=echo-request --permanent
sudo firewall-cmd --remove-icmp-block=echo-reply --permanent

echo 'To get DNS resolution working, simply enable Masquerading.'
sudo firewall-cmd --zone=public  --add-masquerade --permanent

firewall-cmd --reload