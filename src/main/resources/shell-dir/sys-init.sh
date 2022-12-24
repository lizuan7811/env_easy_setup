#!/bin/bash
timedatectl set-ntp yes
timedatectl set-timezone Asia/Taipei
timedatectl show
swapoff -a
sed -i 's/.*swap.*/#&/' /etc/fstab

cat > /etc/NetworkManager/conf.d/rke2-canal.conf << EOF
[keyfile]
unmanaged-devices=interface-name:cali*;interface-name:flannel*
EOF

systemctl reload NetworkManager.service

cat > /etc/sysctl.conf << EOF
net.bridge.bridge-nf-call-ip6tables=1
net.bridge.bridge-nf-call-iptables=1
net.ipv4.ip_forward=1
EOF

modprobe br_netfilter
sysctl -p /etc/sysctl.conf
sysctl --system