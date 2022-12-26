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
