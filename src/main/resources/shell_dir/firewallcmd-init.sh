#!/bin/bash
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