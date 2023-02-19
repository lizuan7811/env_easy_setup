# 上銀環境安裝手冊

## 前置準備
* 安裝時，皆以Root權限進入安裝。
```shell=
#打開terminal
su -
#輸入密碼後按Enter
```
![](https://i.imgur.com/S1YCRa7.png)
* 安裝資料夾data_vg掛在/apdatas資料夾下。
```shell=
#到/apdatas資料夾
cd /apdatas
#建立子資料夾
 mkdir {datas,env_dir,opt,tls_dir,logs_dir}
  #建立後查看
 ll
```
![](https://i.imgur.com/cHiyQVn.png)
![](https://i.imgur.com/5l8eQBR.png)
![](https://i.imgur.com/QS5kx2n.png)


## DOCKER、Harbor(安裝位置:HostName=PIBADM01)

### Docker安裝
* 先刪除舊有Docker以及相關套件或會引起衝突的套件。
```shell=
#Redhat安裝docker時，可能會有預設安裝的檔案，所以需要先刪除舊的檔案(避免衝突)
sudo yum remove docker \
                  docker-client \
                  docker-client-latest \
                  docker-common \
                  docker-latest \
                  docker-latest-logrotate \
                  docker-logrotate \
                  docker-engine \
                  podman \
                  runc
```
![](https://i.imgur.com/51QERZL.png)

* 建立安裝時使用的存放區資料夾
```shell=
 mkdir -p /apdatas/env_dir/docker_harbor_dir
 #移動到子資料夾中
 cd /apdatas/env_dir/docker_harbor_dir/
```
![](https://i.imgur.com/XxZcTjH.png)

* 將佈署使用的檔案傳入資料夾中，並查看。
```shell=
#檔案已傳入後，使用指令查看
ll
```
![](https://i.imgur.com/WM1bBlk.png)

* 解壓縮安裝包
```shell=
tar zxvf docker-plugins.tar.gz 
tar zxvf harbor.tar.gz 

```
![](https://i.imgur.com/0YjF5Lm.png)
![](https://i.imgur.com/gz3sns3.png)




```shell=
# 進入docker-plugins資料夾中，離線安裝rpm檔案
cd docker-plugins/
rpm -ivh *.rpm


```
![](https://i.imgur.com/4AzMi7w.png)

*安裝若不成功，使用下列指令安裝
```shell=
#若安裝不成功，則使用
rpm -ivh *.rpm --force
#安裝後查看狀態
ll
```
![](https://i.imgur.com/FP1kyKo.png)

* 安裝後啟動docker，並設定自啟動
```shell=
systemctl enable docker.service 
systemctl start docker.service 
systemctl status docker.service 
```
![](https://i.imgur.com/kqTMIXU.png)
![](https://i.imgur.com/Hkc9dJe.png)

### Harbor安裝

* harbor安裝時的檔案會放到/apdatas/harbor/資料夾
```shell=
#將解壓縮後的harbor資料夾放到 data_vg 中。
mv harbor /apdatas/opt/
#查看
ll /apdatas/opt/
```
![](https://i.imgur.com/W8dENqv.png)

* 修改harbor.yml環境設定檔案harbor.yml
```shell=
cd /apdatas/opt/harbor
ll
#將官方提供的範例複製一份作修改，檔名結尾務必為**.yml**。
cp harbor.yml.tmpl harbor.yml

#進入檔案作修改，編輯工具若有vim就選擇vim(較好辨別)，若無則選擇vi。
vim harbor.yml
```
![](https://i.imgur.com/CnHJdHw.png)
![](https://i.imgur.com/EFx3woc.png)
* 範例內容(未修改)
![](https://i.imgur.com/BR8o82q.png)
* 修改後內容
![](https://i.imgur.com/CYZ7Yhp.png)

> 需修改項目有: 
> hostname
> 把http註解掉
> https.port
> https.port.certificate
> https.port.private_key
> external_url
> harbor_admin_password
> data_volume
> log.local.location
```shell=
#修改完畢要保存資料
#esc 鍵退出insert模式
#shift + 冒號
#輸入wq(儲存並退出檔案)
:wq
```
![](https://i.imgur.com/bokKv7Z.png)
![](https://i.imgur.com/5gl1eR3.png)
![](https://i.imgur.com/06HdNZN.png)
![](https://i.imgur.com/RnkqasC.png)


* 修改完config，使用docker匯入harbor官方提供，安裝所使用的image
```shell=
docker load --input harbor.v2.6.1.tar.gz 
```
![](https://i.imgur.com/bxlZ5WK.png)
![](https://i.imgur.com/71XSTTU.png)

* 準備harbor與docker要使用的憑證

```shell=
#建立儲存憑證的子資料夾，到/apdatas/tls_dir/harbor_tls
mkdir /apdatas/tls_dir/harbor_tls
cd /apdatas/tls_dir/harbor_tls
```
```shell=
#產Docker、Harbor使用的TLS
##產出ca.key((privateKey))、ca.crt((publicKey))(增加-nodes參數，代表若已存在key則會直接覆蓋)
openssl req \
    -newkey rsa:4096 -nodes -sha256 -keyout ca.key \
    -x509 -days 3650 -out ca.crt \
    -subj "/C=TW/ST=Taiwan/L=Taiwan/O=Pershiung/OU=DFU/CN=192.168.112.94/CN=192.168.112.86/CN=192.168.112.87/CN=192.168.112.88/emailAddress=dfumail@gmail.com"
##產出第二組給client使用的key跟證書申請文件(.csr)。
openssl req \
    -newkey rsa:4096 -nodes -sha256 -keyout harbor-registry.key \
    -out harbor-registry.csr \
    -subj "/C=TW/ST=Taiwan/L=Taiwan/O=Pershiung/OU=DFU/CN=192.168.112.94/CN=192.168.112.86/CN=192.168.112.87/CN=192.168.112.88/emailAddress=dfumail@gmail.com"
```
![](https://i.imgur.com/ZEnBDNJ.png)

```shell=
## 產出.ext檔案(是certification extension)證書擴展。
cat > v3.ext <<-EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth,clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1=pibadm01
DNS.2=pibmid01
DNS.3=pibmid02
DNS.4=pibmid03
DNS.5=localhost
IP.1 =192.168.112.94
IP.2 =192.168.112.86
IP.3 =192.168.112.87
IP.4 =192.168.112.88
EOF
```
![](https://i.imgur.com/gxwusod.png)

```shell=
#若有多個Client需要連接，就需要寫入多個IP。
#ectAltName = IP:172.168.113.110 > extfile.cnf 
#使用第一組產出的ca.key跟ca.crt對第二組產出的.csr證書申請做認證並增加.ext作為證書的擴展，最後產出證書序號跟.crt證書(經簽發的證書)
openssl x509 -req -days 365 -in harbor-registry.csr -CA ca.crt -CAkey ca.key -CAcreateserial -extfile v3.ext -out harbor-registry.cert
#將最末產出的自簽證書轉為PEM格式
#指令格式openssl x509 -inform PEM -in yourdomain.com.crt -out yourdomain.com.cert
openssl x509 -inform PEM -in harbor-registry.cert -out harbor-registry.pem
```
![](https://i.imgur.com/ILFB7uN.png)

* 將產出的憑證存到docker預設讀取的資料夾
```shell=
IP=($(ifconfig | grep -A 1 'ens33' | tail -1 | cut -d ':' -f 2 ))
DOCKER_DIR=/etc/docker/certs.d/${IP[1]}
if [ “${IP[1]}” != “” ] 
then
	echo 'find ipaddress and create ipaddress_name folder, finally copy the keys to the folder'
    mkdir -p $DOCKER_DIR
    cp {*.crt,*.key,*.cert,*.csr,*.pem} $DOCKER_DIR
else
	echo 'not find ipadd, need to writer correct card name!'
fi
```
![](https://i.imgur.com/ebzdp7h.png)


* 重啟docker.service
```shell=
systemctl daemon-reload
systemctl restart docker.service
```
![](https://i.imgur.com/fgES30I.png)

    
 * 執行harbor
```shell=
cd /apdatas/opt/harbor
./prepare
```

![](https://i.imgur.com/LFcmde3.png)
```shell=
./install.sh
```
![](https://i.imgur.com/f4cxUxX.png)

![](https://i.imgur.com/lltjfHX.png)

![](https://i.imgur.com/rIVDWA9.png)

* harbor 啟動指令
```shell=
#需在harbor資料夾下指令
#啟動harbor
docker compose up -d

#關閉harbor
docker compose down -v
```
* 登入docker帳號
```shell=
docker login https://192.168.112.94:443
```
![](https://i.imgur.com/qjIdPrA.png)

* docker 匯入提供離線安裝使用的images，push至harbor

* 會使用到的images預先準備好成zip檔，需解壓縮後，使用下列指令依序讀入docker。
![](https://i.imgur.com/SfuehlY.png)
```shell=
mkdir /apdatas/opt/images_dir
cd /apdatas/opt/images_dir
#解壓縮zip檔案至目前的資料夾
unzip -d . ImagesToHarbor1.zip
unzip -d . ImagesToHarbor2.zip
unzip -d . RKE2Images安裝.zip
#查看
ll
```
![](https://i.imgur.com/Uoe4Wa3.png)

```shell=
#將鏡像檔讀入docker
for filename in *.tar*; do
docker load --input $filename;
done
```
![](https://i.imgur.com/j7sdGeP.png)

```shell=
#列出images的列表，存成txt，並依序標記tag後，push到harbor
docker images > images.txt
while read line; do tmpL=($line); tagL="192.168.112.94:443/library/"${tmpL[0]}:${tmpL[1]}; echo ${tmpL[0]}:${tmpL[1]} >> resources_images.txt; echo $tagL >> tag_images.txt; docker tag ${tmpL[0]}:${tmpL[1]} $tagL; done < images.txt
```
![](https://i.imgur.com/YtbBAoK.png)
```shell=
#psuh 已被tag的字串，push到harbor
while read line; do docker push $line; done < tag_images.txt
```
* push images會需要一段時間，可以先準備安裝RKE2的部分。
![](https://i.imgur.com/8AFlpI7.png)
```shell=
#push 完畢刪除images
while read line; do docker rmi $line; done < tag_images.txt
while read line; do docker rmi $line; done < resources_images.txt
```
![](https://i.imgur.com/s1f0H7T.png)

![](https://i.imgur.com/Bz3vUtg.png)

![](https://i.imgur.com/VAg5OaF.png)

* 將安裝harbor產出的ca.crt、harbor-registry.key、harbor-registry.cert傳給pibmid01
---
### 安裝RKE2(hostname=pibmid01、 pibmid02、pibmid03)

* **RKE2安裝前置作業**

* 設定hostname
```shell=
#設定hostname，這裡使用pibmid01(其他安裝RKE2的機器，依序設定為02、03...)
hostnamectl set-hostname pibmid01
hostname
```
![](https://i.imgur.com/pnXXzA4.png)
* 建立存放資料以及佈署檔案的子資料夾
```shell=
mkdir /apdatas/{env_dir,logs_dir,tls_dir}
mkdir -p /apdatas/ap/rancher
ll /apdatas/
```
![](https://i.imgur.com/ps9GusA.png)

* 設定系統時間及網路防火牆

```shell=
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
cat > /etc/NetworkManager/conf.d/rke2-canal.conf << EOF
[keyfile]
unmanaged-devices=interface-name:cali*;interface-name:flannel*
EOF

#重新reload NetworkManager.service
systemctl reload NetworkManager.service

#防火牆設定
tcpports=(22 443 9345 6443 10250 2379 2380 30000-32767 179 5473 9098 9099 10254 9100 9300 6379 6380 26379 8600 8501 8301 8302 8300 8080 8081 5555 18080 18081 15555)
udpports=(4789 8600 8301 8302)

for pt in "${tcpports[@]}"; do
firewall-cmd --zone=public --permanent --add-port=$pt/tcp
done

for pt in "${udpports[@]}"; do
firewall-cmd --zone=public --permanent --add-port=$pt/udp
done

firewall-cmd --remove-icmp-block=echo-request --permanent
firewall-cmd --remove-icmp-block=echo-reply --permanent
### To get DNS resolution working, simply enable Masquerading.
firewall-cmd --zone=public  --add-masquerade --permanent

firewall-cmd --reload
```
* 若已將有部分port開過，則會顯示**ALREADY_ENABLED**
![](https://i.imgur.com/RB1L6Jz.png)
```shell=
#網路傳輸設定
cat > /etc/sysctl.conf << EOF
net.bridge.bridge-nf-call-ip6tables=1
net.bridge.bridge-nf-call-iptables=1
net.ipv4.ip_forward=1
EOF

##讓設定生效
modprobe br_netfilter
sysctl -p /etc/sysctl.conf
sysctl --system

```
![](https://i.imgur.com/4EneZKC.png)

* 建立registries.yaml檔案至/etc/rancher/rke2/資料夾中，若資料夾不存在，則建立資料夾。
```shell=
#設定讓RKE2 從private registry中pull image
# 建立rke2安裝時，檔案存放預設的資料夾
mkdir -p /etc/rancher/rke2
#建立registries.yaml，讓rke2可以從harbor上pull images
cat > /etc/rancher/rke2/registries.yaml <<EOF
mirrors:
  docker.io:
    endpoint:
      - https://192.168.112.94:443
    rewrite:
      "^rancher/(.*)": "library/rancher/$1"
  "192.168.112.94:443":
    endpoint:
      - https://192.168.112.94:443
    rewrite:
      "/(.*)": "/$1"
configs:
  "192.168.112.94:443":
    auth:
      username: admin
      password: Admin@@@111
    tls:
      cert_file: /apdatas/tls_dir/harbor_tls/harbor-registry.cert # path to the cert file used to authenticate to the registry
      key_file: /apdatas/tls_dir/harbor_tls/harbor-registry.key # path to the key file for the certificate used to authenticate to the registry
      ca_file: /apdatas/tls_dir/harbor_tls/ca.crt # path to the ca file used to verify the registry's certificate
      insecure_skip_verify: true # may be set to true to skip verifying the registry's certificate
EOF

#查看檔案內容
cat /etc/rancher/rke2/registries.yaml
```
* 確認$1要有
![](https://i.imgur.com/xsHDa5k.png)

* 將pibadm01傳過來的key跟憑證放到/apdatas/tls_dir/harbor_tls/中並查看資料夾
```shell=
mkdir -p /apdatas/tls_dir/harbor_tls
mv *.{key,crt,cert} /apdatas/tls_dir/harbor_tls/
ll
```
![](https://i.imgur.com/lGVxuzz.png)

```shell=
#將要安裝的RPM檔案存到/apdatas/env_dir/rke2_install/資料夾中，執行解壓縮後安裝
mkdir /apdatas/env_dir/rke2_install/
mv rke2-install-rpms.tar.gz /apdatas/env_dir/rke2_install/
cd /apdatas/env_dir/rke2_install/
tar zxvf rke2-install-rpms.tar.gz
tree .
```
![](https://i.imgur.com/J8TdNTa.png)

* 安裝rpm檔案
```shell=
cd rke2-packages
rpm -ivh *.rpm
#若有安裝衝突，則使用rpm -ivh *.rpm --force取代。(下圖使用--force是因先前已安裝過rke2)
```
![](https://i.imgur.com/4kX47IY.png)
* 將cis.conf檔案複製到/etc/sysctl.d/ 並讓systemd-sysctl 重啟，使設定生效。
```shell=
sudo cp -f /usr/share/rke2/rke2-cis-sysctl.conf /etc/sysctl.d/60-rke2-cis.conf
sudo systemctl restart systemd-sysctl
```
* 新增etcd user。
```shell=
sudo useradd -r -c "etcd user" -s /sbin/nologin -M etcd -U
```
![](https://i.imgur.com/9D73DDI.png)
* 設定rke2使用的config.yaml
```shell=
mkdir -p /etc/rancher/rke2
cat << EOF >  /etc/rancher/rke2/config.yaml
write-kubeconfig-mode: "0644"
#profile: "cis-1.6"
#若使用data-dir，selinux虛設為false，否則無權限修改。
selinux: false
#安裝到指定路徑
data-dir: "/apdatas/ap/rancher/rke2"
# add ips/hostname of hosts and loadbalancer
tls-san:
  - 192.168.112.86
  - tnibmid01
# Make a etcd snapshot every 12 hours
etcd-snapshot-schedule-cron: " */12 * * *"
# Keep 2 etcd snapshorts (equals to 1 weekswith 2 a day)
etcd-snapshot-retention: 14
cni:
  - calico
disable:
  - rke2-canal
  - rke2-kube-proxy
EOF
cat /etc/rancher/rke2/config.yaml
```
![](https://i.imgur.com/d6oySDZ.png)
* 調整rke2 log儲存的位置
```shell=
#查看資料夾下是否有containers、pods資料夾
#若資料夾原本不存在，則使用下列指令******************
mkdir /apdatas/logs_dir/{containers,pods}
ln -s /apdatas/logs_dir/containers /var/log/
ln -s /apdatas/logs_dir/pods /var/log/

#**********************************************
#若資料夾已存在，則使用下列指令*********************
mv /var/log/pods /apdatas/logs_dir
mv /var/log/containers /apdatas/logs_dir
ln -s /apdatas/logs_dir/containers /var/log/
ln -s /apdatas/logs_dir/pods /var/log/
#**********************************************
ll /var/log/
```
![](https://i.imgur.com/Zr9kfKv.png)
```shell=
ll /apdatas/logs_dir/
```
![](https://i.imgur.com/zdPNDNe.png)
```shell=
#安裝RKE2 rpm 檔案，啟動RKE2，第一台RKE2直接啟動即可。
systemctl start rke2-server.service
systemctl enable rke2-server.service
export KUBECONFIG=/etc/rancher/rke2/rke2.yaml 
#or
ln -s /etc/rancher/rke2/rke2.yaml /root/.kube/config
#測試RKE2建立後的結果
/var/lib/rancher/rke2/bin/kubectl get node
#or
ln -s /var/lib/rancher/rke2/bin/ctr /usr/local/bin/ctr
ln -s /var/lib/rancher/rke2/bin/kubectl /usr/local/bin/kubectl
ln -s /var/lib/rancher/rke2/bin/crictl /usr/local/bin/crictl
```
```shell=
systemctl status rke2-server.service
```
![](https://i.imgur.com/dkQkcZZ.png)
```shell=
kubectl get node
```
![](https://i.imgur.com/F5pUxwf.png)
```shell=
kubectl get pod -A
```
![](https://i.imgur.com/iz36rVK.png)

* 取RKE2 token，將token複製至config.yaml
```shell=
cat /apdatas/ap/rancher/rke2/server/token > pibmid01-rke2token.txt
#把token傳給第二台要安裝RKE2的機器
```
![](https://i.imgur.com/ClPcgLb.png)

* pibmid02、pibmid03安裝時，config.yaml內容不同，安裝第二台以後的機器，修改config.yaml，並在修改完之後再啟動rke2-server。
```shell=
#查第一台rke2的token
cat /etc/rke2/server/token
```
![](https://i.imgur.com/ClPcgLb.png)
> 修改內容如下:
> server: https://+第一台rke2的ip+:9345
> token: 第一台rke2的token值
* 修改後存入對應的位置，再啟動rke2-server。
```shell=
mkdir -p /etc/rancher/rke2
cat << EOF >  /etc/rancher/rke2/config.yaml
server: https://192.168.112.86:9345
token: K10e28502d0dad9325f52fe84a144b56f70c39938aa7fe8f195eb1d9f2d2aad4401::server:31c7dc103a928a101e9f26ced30ff7bf
write-kubeconfig-mode: "0644"
data-dir: "/apdatas/ap/rancher/rke2"
#profile: "cis-1.6"
selinux: true
# add ips/hostname of hosts and loadbalancer
tls-san: 
  - 192.168.112.86
  - tnibmid01
# Make a etcd snapshot every 12 hours
etcd-snapshot-schedule-cron: " */12 * * *"
# Keep 14 etcd snapshorts (equals to 1 week with 7 a day)
etcd-snapshot-retention: 14
cni:
  - calico
disable:
  - rke2-canal
  - rke2-kube-proxy
EOF
```

* 三台均完成安裝後，於pibmid01查看cluster STATUS，Ready即正常。
```shell=
# 查node
kubectl get node
```
![](https://i.imgur.com/CjQ4E9E.png)
```shell=
# 查pod
kubectl get pod -A
```
![](https://i.imgur.com/IONFmvg.png)

* **若RKE2群安裝不成功且無法判斷原因，可使用下列指令清空RKE2及相關資料重新安裝**
```shell=
#rke2內建清除指令
rke2-kill.sh
#rke2內建解除安裝指令
rke2-uninstall.sh
#手動刪除殘留的檔案
rm -rf /apdatas/ap/rancher/*
rm -rf /apdatas/logs_dir/containers/*
rm -rf /apdatas/logs_dir/pods/*
ln -s /apdatas/logs_dir/containers /var/log/
ln -s /apdatas/logs_dir/pods /var/log/
```
---
## 安裝客戶端資料收集區
* **建立個別資料夾**
```shell=
mkdir /apdatas/{opt,env_dir,logs_dir}/{kafka,prometheus,kibana,elasticsearch,grafana}

mkdir /apdatas/tls_dir/{kafka_tls,prometheus_tls,kibana_tls,elastic_tls,grafana_tls}
```

* 設定Elasticsearch、Kibana、Kafka、Prometheus、Grafana防火牆
```shell=
tcpports=(9200 5601 9092 9093 8084 9090 9300 3000)

for pt in "${tcpports[@]}"; do
firewall-cmd --zone=public --permanent --add-port=$pt/tcp
done

firewall-cmd --reload
```

### KAFKA安裝
* **產Kafka Certificate**
[KeyUsage參數說明](https://www.ibm.com/docs/en/external-auth-server/2.4.2?topic=extensions-keyusage-extension)
* 建立kafka使用的憑證
```shell=
cd /apdatas/tls_dir/kafka_tls
openssl req -newkey rsa:4096 -nodes -sha256 -keyout ca.key -x509 -days 3650 -out ca.crt -subj "/C=TW/ST=Taiwan/L=Taiwan/O=Pershiung/OU=DFU/CN=192.168.112.90/CN=192.168.112.91/CN=192.168.112.92/emailAddress=ptsc@gmail.com"
#使用keytool 產生一組key(private、public)並存在keystore中。
keytool -keystore kafka.keystore.jks -alias CAKafka -validity 3650 -genkey -keyalg RSA -storepass 1qaz@WSX
```
![](https://i.imgur.com/dkgg2bK.png)
```shell=
#使用keytool產出申請證書簽證使用的.csr檔案
keytool -keystore kafka.keystore.jks -alias CAKafka -certreq -file kafka-unsigned.csr -storepass 1qaz@WSX
```
![](https://i.imgur.com/dbLFqA6.png)

```shell=
cat > v3.ext <<-EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth,clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1=pibagt01
DNS.2=pibagt02
DNS.3=pibagt03
DNS.5=localhost
IP.1 =192.168.112.90
IP.2 =192.168.112.91
IP.3 =192.168.112.92
EOF
#使用第一組產出的key(public、private)對申請證書的檔案作簽證，並添加證書擴展後，產出證書。
```
![](https://i.imgur.com/6zNMJqd.png)
```shell=
openssl x509 -req -CA ca.crt -CAkey ca.key -in kafka-unsigned.csr -days 3650 -CAcreateserial -extfile v3.ext -out kafka-signed.crt 
```
![](https://i.imgur.com/Tk4QQq5.png)
```shell=
#將原始CA匯入keystore
keytool -keystore kafka.keystore.jks -alias CARoot -import -file ca.crt -storepass 1qaz@WSX
```
![](https://i.imgur.com/I5qVGmP.png)
```shell=
#將簽證過的CAKAFKA匯入keystore
keytool -keystore kafka.keystore.jks -alias CAKafka -import -file kafka-signed.crt -storepass 1qaz@WSX
```
![](https://i.imgur.com/imyyM3G.png)
```shell=
#將kafka-ca.crt加入至kafka.truststore.jks中
keytool -keystore kafka.truststore.jks -alias CARoot -import -file ca.crt -storepass 1qaz@WSX
```
![](https://i.imgur.com/LOBhw4V.png)
```shell=
keytool -keystore kafka.truststore.jks -alias CAKafka -import -file kafka-signed.crt -storepass 1qaz@WSX

ll
```
![](https://i.imgur.com/AwSfrQL.png)

![](https://i.imgur.com/FJTSqts.png)


* 準備好憑證後，就開始調整kafka的config files
> 1.把安裝用壓縮檔放到/env_dir/kafka下解壓縮至/apdatas/opt/kafka/
```shell=
tar zxvf kafka_2.13-3.3.2.tgz -C /apdatas/opt/kafka/
mkdir /apdatas/opt/kafka/kafka_2.13-3.3.2/plugins
tar zxvf confluentinc-kafka-connect-elasticsearch-14.0.2.tar.gz -C /apdatas/opt/kafka/kafka_2.13-3.3.2/plugins/
cd /apdatas/opt/kafka/kafka_2.13-3.3.2/
ll 
```
![](https://i.imgur.com/W7Wq8nh.png)

![](https://i.imgur.com/sdjyth4.png)

![](https://i.imgur.com/LbHJtle.png)

* 修改config檔案
```shell=
vim config/kraft/broker.properties 
vim config/kraft/controller.properties 
vim config/kraft/server.properties 
```
* 下列properties或yaml(yml)僅列出更動的參數，其餘參數為預設。

* config/kraft/server.properties
* **修改前**:
```shell=
process.roles=broker,controller
node.id=1
controller.quorum.voters=1@localhost:9093
listeners=PLAINTEXT://:9092,CONTROLLER://:9093
inter.broker.listener.name=PLAINTEXT
advertised.listeners=PLAINTEXT://localhost:9092
controller.listener.names=CONTROLLER
listener.security.protocol.map=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT,SSL:SSL,SASL_PLAINTEXT:SASL_PLAINTEXT,SASL_SSL:SASL_SSL
log.dirs=/tmp/kraft-combined-logs
num.partitions=1
offsets.topic.replication.factor=3
transaction.state.log.replication.factor=3
transaction.state.log.min.isr=3
```

* **修改後**:
```shell=
process.roles=broker,controller
node.id=1
controller.quorum.voters=1@192.168.112.90:9093,2@192.168.112.91:9093,3@192.168.112.92:9093
listeners=SSL://192.168.112.90:9092,CONTROLLER://192.168.112.90:9093
#inter.broker.listener.name=SSL
advertised.listeners=SSL://192.168.112.90:9092
controller.listener.names=CONTROLLER
listener.security.protocol.map=CONTROLLER:SSL,PLAINTEXT:PLAINTEXT,SSL:SSL,SASL_PLAINTEXT:SASL_PLAINTEXT,SASL_SSL:SASL_SSL
log.dirs=/apdatas/logs_dir/kafka/kraft-combined-logs
num.partitions=6
offsets.topic.replication.factor=3
transaction.state.log.replication.factor=3
transaction.state.log.min.isr=3
#===Security===
ssl.keystore.location=/apdatas/tls_dir/kafka/kafka.keystore.jks
ssl.keystore.password=1qaz@WSX
ssl.key.password=1qaz@WSX
ssl.truststore.location=/apdatas/tls_dir/kafka/kafka.truststore.jks
ssl.truststore.password=1qaz@WSX
ssl.enabled.protocols=TLSv1.2,TLSv1.1,TLSv1
ssl.client.auth=requested
security.inter.broker.protocol=SSL
```
![](https://i.imgur.com/bFaBJuD.png)

![](https://i.imgur.com/Ihy2Xn0.png)
![](https://i.imgur.com/NeS6nsZ.png)
![](https://i.imgur.com/8O26f0a.png)

* config/kraft/controller.properties

* **修改前**:
```shell=
node.id=1
controller.quorum.voters=1@localhost:9093
listeners=CONTROLLER://:9093
controller.listener.names=CONTROLLER
log.dirs=/tmp/kraft-controller-logs
num.partitions=1
offsets.topic.replication.factor=1
transaction.state.log.replication.factor=1
transaction.state.log.min.isr=1
log.segment.bytes=1073741824
log.retention.check.interval.ms=300000
```
* **修改後**:
```shell=
#若是安裝第二台(第三台)，node.id須改為2或3，與controller.qurorm.voters中的node 1、2、3的IP互相對應。
node.id=1
controller.quorum.voters=1@192.168.112.90:9093,2@192.168.112.91:9093,3@192.168.112.92:9093
#目前這一台機器的IP
listeners=CONTROLLER://192.168.112.90:9093
log.dirs=/apdatas/logs_dir/kafka/kraft-controller-logs
num.partitions=6
num.recovery.threads.per.data.dir=1
offsets.topic.replication.factor=3
transaction.state.log.replication.factor=3
transaction.state.log.min.isr=3
```

* config/kraft/broker.properties
* **修改前**:
```shell=
node.id=2
controller.quorum.voters=1@localhost:9093
listeners=PLAINTEXT://localhost:9092
inter.broker.listener.name=PLAINTEXT
advertised.listeners=PLAINTEXT://localhost:9092
listener.security.protocol.map=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT,SSL:SSL,SASL_PLAINTEXT:SASL_PLAINTEXT,SASL_SSL:SASL_SSL
log.dirs=/tmp/kraft-broker-logs
num.partitions=1
offsets.topic.replication.factor=1
transaction.state.log.replication.factor=1
transaction.state.log.min.isr=1
```
* **修改後**:
```shell=
node.id=1
controller.quorum.voters=1@192.168.112.90:9093,2@192.168.112.91:9093,3@192.168.112.92:9093
listeners=SSL://192.168.112.90:9092
inter.broker.listener.name=SSL
advertised.listeners=SSL://192.168.112.90:9092
listener.security.protocol.map=CONTROLLER:SSL,PLAINTEXT:PLAINTEXT,SSL:SSL,SASL_PLAINTEXT:SASL_PLAINTEXT,SASL_SSL:SASL_SSL
num.network.threads=3
num.io.threads=8
socket.send.buffer.bytes=102400
socket.receive.buffer.bytes=102400
socket.request.max.bytes=104857600
log.dirs=/apdatas/logs_dir/kafka/kraft-broker-logs
num.partitions=6
offsets.topic.replication.factor=3
transaction.state.log.replication.factor=3
transaction.state.log.min.isr=3
#======SECURITY===========
ssl.keystore.location=/apdatas/tls_dir/kafka/kafka.keystore.jks
ssl.keystore.password=1qaz@WSX
ssl.key.password=1qaz@WSX
ssl.truststore.location=/apdatas/tls_dir/kafka/kafka.truststore.jks
ssl.truststore.password=1qaz@WSX
ssl.enabled.protocols=TLSv1.2,TLSv1.1,TLSv1
ssl.client.auth=requested
security.inter.broker.protocol=SSL
```
* config/connect-distribute.properties
* **修改前**
```shell=
bootstrap.servers=localhost:9092
group.id=connect-cluster
key.converter=org.apache.kafka.connect.json.JsonConverter
value.converter=org.apache.kafka.connect.json.JsonConverter
key.converter.schemas.enable=true
value.converter.schemas.enable=true
##把#去掉
#listeners=HTTP://:8083
##把#去掉
#plugin.path=
```
* **修改後**
```shell=
bootstrap.servers=192.168.112.90:9092,192.168.112.91:9092,192.168.112.92:9092
group.id=connect-cluster
key.converter=org.apache.kafka.connect.json.JsonConverter
value.converter=org.apache.kafka.connect.json.JsonConverter
key.converter.schemas.enable=false
value.converter.schemas.enable=false
listeners=HTTPS://192.168.112.90:8084
plugin.path=/apdatas/opt/kafka/kafka_2.13-3.3.2/plugin/confluentinc-kafka-connect-elasticsearch-14.0.2/,/usr/lib/jvm/java-11-openjdk-11.0.17.0.8-2.el8_6.x86_64/
key.ignore=true
type.name=kafka-connect
connection.url=https://192.168.112.90:9200
connection.username=elastic
connection.password=1qaz@WSX
topircs=kafka-connect-elastic

ssl.keystore.location=/apdatas/tls_dir/kafka_tls/kafka.keystore.jks
ssl.keystore.password=1qaz@WSX
ssl.key.password=1qaz@WSX
ssl.truststore.location=/apdatas/tls_dir/kafka_tls/kafka.truststore.jks
ssl.truststore.password=1qaz@WSX
ssl.keystore.type=JKS
ssl.truststore.type=JKS
ssl.enabled.protocols=TLSv1.2,TLSv1.1,TLSv1
ssl.client.auth=required
security.protocol=SSL
producer.security.protocol=SSL
consumer.security.protocol=SSL
```

* 執行初始化broker
使用kafka內建工具取得一組做為cluster的id，所以若要使node在同一個cluster，就需要在其他node上使用同一組uuid初始化server.properties。
```shell=
#這組uuid要給同一組kfaka cluster使用
./bin/kafka-storage.sh random-uuid

./bin/kafka-storage.sh format -t <uuid> -c ./config/kraft/server.properties
```
![](https://i.imgur.com/LCbgka0.png)

![](https://i.imgur.com/f0avlce.png)

![](https://i.imgur.com/j8n6fv9.png)

![](https://i.imgur.com/FfZoJf8.png)

* 啟動kafka
```shell=
#前台執行
./bin/kafka-server-start.sh config/kraft/server.properties
#背景執行指令
nohup ./bin/kafka-server-start.sh config/kraft/server.properties >/dev/null 2>&1
```
* 執行結果未報出error則成功佈署。
![](https://i.imgur.com/1ZxbpGD.png)

---
### Elasticsearch

* 解壓縮
```shell=
 tar zxvf elasticsearch-7.17.7-linux-x86_64.tar.gz -C /apdatas/opt/elasticsearch/
 cd /apdatas/opt/elasticsearch/
 ll
```
![](https://i.imgur.com/DrvYPDb.png)
![](https://i.imgur.com/HxsiD6W.png)

* **Elasticsearch以及Kibana都無法在root權限下執行，需建立使用者並給予使用者權限執行，啟動程式時，需先登入elastic user帳戶**。
```shell=
useradd elastic
#設定密碼
gpasswd elastic
#授予資料夾權限
mkdir /apdatas/opt/elasticsearch/elastic_datas
chown -R elastic /apdatas/opt/elasticsearch/elastic_datas
chown -R elastic /apdatas/logs_dir/elasticsearch/
chown -R elastic /apdatas/opt/elasticsearch/
chown -R elastic /apdatas/opt/elasticsearch/elasticsearch-7.17.7/config/
chown -R elastic /apdatas/opt/elasticsearch/elasticsearch-7.17.7/

```
![](https://i.imgur.com/sP0hbxH.png)


* 修改elasticsearch.yml
```yml=
vim config/elasticsearch.yml

#同一個cluster使用同一個名字
cluster.name: pibagt-cluster
#使用hostname作為nodename
node.name: pibagt01
#使用預設即可
node.attr.rack: r1
path.data: /apdatas/opt/elasticsearch/elastic_datas
path.logs: /apdatas/logs_dir/elasticsearch/elastic_logs
network.host: 192.168.112.90
http.port: 9200
#http.cors.enabled: true
#http.cors.allow-origin: "*"
#http.max_content_length: 200mb
transport.tcp.port: 9300
transport.tcp.compress: false
#network.tcp.keep_alive: true
#network.tcp.reuse_address: true
#network.tcp.send_buffer_size: 256mb
#network.tcp.receive_buffer_size: 256mb
#gateway.recover_after_nodes: 2
discovery.seed_hosts: ["192.168.112.90","192.168.112.91","192.168.112.92"]
discovery.zen.minimum_master_nodes: 2
cluster.initial_master_nodes: ["pibagt01","pibagt02","pibagt03"]
cluster.join.timeout: 30s
cluster.publish.timeout: 90s
cluster.routing.allocation.cluster_concurrent_rebalance: 16
cluster.routing.allocation.node_concurrent_recoveries: 16
cluster.routing.allocation.node_initial_primaries_recoveries: 16
node.master: true
node.data: true
ingest.geoip.downloader.enabled: false
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.keystore.path: /apdatas/opt/elasticsearch/elasticsearch-7.17.7/config/elasticsearch.p12
xpack.security.transport.ssl.truststore.path: /apdatas/opt/elasticsearch/elasticsearch-7.17.7/config/elasticsearch.p12
xpack.security.http.ssl.enabled: true
xpack.security.http.ssl.keystore.path: /apdatas/opt/elasticsearch/elasticsearch-7.17.7/config/http.p12
xpack.security.enabled: true
xpack.security.http.ssl.client_authentication: optional 
xpack.security.http.ssl.verification_mode: certificate
xpack.security.authc.realms.pki.pki1.order: 1
```




```shell=
cat > instance.yaml <<EOF
instances:
  - name: elasticsearch
    dns: 
      - localhost
      - pibagt01
      - pibagt02
      - pibagt03
    ip:
      - 192.168.112.90
      - 192.168.112.91
      - 192.168.112.92
EOF

```
![](https://i.imgur.com/bWoh70Z.png)


```shell=
#產生key，使用產kafka時的ca.crt及ca.key
./bin/elasticsearch-certutil cert --ca-cert /apdatas/tls_dir/kafka_tls/ca.crt --ca-key /apdatas/tls_dir/kafka_tls/ca.key -in instance.yaml --days 3650 --out certificate.zip
```
![](https://i.imgur.com/956YhiO.png)

![](https://i.imgur.com/dAox5Kr.png)
```shell=
#建立給client使用的憑證，是為了給kibana使用，這裡使用kafka產出時的ca.key以及ca.crt
./bin/elasticsearch-certutil http 

```
* 執行指令後，需要輸入一些參數，第一個選擇n(不需要產出csr檔案)，後續依提示輸入資料，此處將key size改為4096，密碼為1qaz@WSX。
![](https://i.imgur.com/mvKZwX3.png)
![](https://i.imgur.com/8KIJC6l.png)
![](https://i.imgur.com/btzPxaE.png)
![](https://i.imgur.com/9J3Ywml.png)
![](https://i.imgur.com/2n0E2o7.png)
![](https://i.imgur.com/X9jargf.png)


![](https://i.imgur.com/D3TAHtv.png)
![](https://i.imgur.com/UJM54VA.png)


![](https://i.imgur.com/muN3G2G.png)


```shell=
#將檔案解壓縮至./config資料夾，再將壓縮檔移到/apdatas/tls_dir/elastic_tls

unzip -d ./config certificate.zip
unzip -d ./config elasticsearch-ssl-http.zip

mv certificate.zip /apdatas/tls_dir/elastic_tls/

mv config/elasticsearch/elasticsearch.p12 config/

mv config/elasticsearch/http.12 config/

mv elasticsearch-ssl-http.zip /apdatas/tls_dir/elastic_tls/
```
![](https://i.imgur.com/0mjo51y.png)
![](https://i.imgur.com/nfM5HVn.png)



![](https://i.imgur.com/P5Yn9FW.png)


```shell=

#建立keystore儲存密碼，此處預設為1qaz@WSX
./bin/elasticsearch-keystore add xpack.security.transport.ssl.keystore.secure_password

./bin/elasticsearch-keystore add xpack.security.transport.ssl.truststore.secure_password
#若產http.p12時有設定密碼，則也需要存入密碼到keystore
./bin/elasticsearch-keystore add xpack.security.http.ssl.keystore.secure_password

./bin/elasticsearch-keystore add xpack.security.http.ssl.truststore.secure_password

```
![](https://i.imgur.com/GTCaRry.png)

![](https://i.imgur.com/c1tQVkF.png)

![](https://i.imgur.com/ToVGuTG.png)

* 執行若是憑證驗證失敗，若無法排除，就重新產elasticsearch key的步驟。
* 需要給予user足夠讀取資料夾的權限。
```shell=
#完成一台安裝後，啟動測試
su elastic
cd /apdatas/opt/elasticsearch/elasticsearch-7.17.7
bin/elasticsearch

# 背景執行
nohup bin/elasticsearch >/dev/null 2>&1
```
![](https://i.imgur.com/xfCarHf.png)
![](https://i.imgur.com/k4wCfhH.png)

* 三台都設定後啟動截圖:
![](https://i.imgur.com/TU00zTK.png)
* 測試
```shell=
curl -k -u elastic https://192.168.112.90:9200
```
![](https://i.imgur.com/rVLhBP0.png)
* terminal測試
![](https://i.imgur.com/xYRk8qR.png)
* 瀏覽器登入
![](https://i.imgur.com/X5X5ln7.png)


### Kibana

* 將安裝檔解壓縮至/apdatas/opt/kibana/
```shell=
tar zxvf kibana-7.17.7-linux-x86_64.tar.gz -c /apdatas/opt/kibana/
```
![](https://i.imgur.com/lpXlP3A.png)

* 準備kibana憑證

* 使用elasticsearch的憑證工具建立提供給kibana使用的憑證相關資料

```shell=
./bin/elasticsearch-certutil csr -name kibana-server -dns pibagt01,pibagt02,pibagt03,192.168.112.90,192.168.112.91,192.168.112.92
```
![](https://i.imgur.com/Lpmggad.png)
```shell=
mv csr-bundle.zip /apdatas/tls_dir/kibana_tls/

cd /apdatas/tls_dir/kibana_tls/

unzip -d . csr-bundle.zip 

ll

ll kibana-server/
```
![](https://i.imgur.com/s9YNa8b.png)


* 將elasticsearch產生的http.p12以及提供給kibana使用的資料產出可用的憑證。
```shell=

#req代表要使用或產出.csr檔案。(若有-new，代表要新增產出.csr)
#這裡用來簽發kibana-server的ca.crt及ca.key是在kafka憑證時產出的檔案。
openssl x509 -req -days 3650 -in kibana-server.csr -CA /apdatas/tls_dir/kafka_tls/ca.crt -CAkey /apdatas/tls_dir/kafka_tls/ca.key -CAcreateserial -extfile /apdatas/tls_dir/kafka_tls/v3.ext -out kibana-server.crt
```
![](https://i.imgur.com/q5Yfl2J.png)


```shell=
#將elasticsearch產出的.p12轉為key、cert
openssl pkcs12 -in http.p12 -nocerts -nodes  > client.key
openssl pkcs12 -in http.p12 -clcerts -nokeys  > client.cer
ll
cp client.* 
```
![](https://i.imgur.com/3mWqiUy.png)

![](https://i.imgur.com/YEQIDsE.png)

![](https://i.imgur.com/67pAftF.png)

![](https://i.imgur.com/3XDgTBM.png)

```shell=
cp /apdatas/opt/elasticsearch/elasticsearch-7.17.7/config/elasticsearch-ca.pem /apdatas/tls_dir/kibana_tls/
cp /apdatas/tls_dir/kibana_tls/client.cer config/
cp /apdatas/tls_dir/kibana_tls/client.key config/
cp /apdatas/tls_dir/kibana_tls/elasticsearch-ca.pem config/
cp /apdatas/tls_dir/kibana_tls/kibana-server/kibana-server.* config/
```
* 使用kibana工具產出encrypt datas，須將下圖紅色框中資料存入kibana.yml檔案
```shell=
bin/kibana-encryption-keys generate
```
![](https://i.imgur.com/FNcD8dK.png)

* 修改kibana.yml檔案
```shell=
vim /apdatas/opt/kibana/kibana-7.17.7-linux-x86_64/config/kibana.yml 
#將讀寫資料夾權限給elastic user
chown -R elastic /apdatas/opt/kibana/kibana-7.17.7-linux-x86_64
chown -R elastic /apdatas/opt/kibana/kibana-7.17.7-linux-x86_64/config
```
![](https://i.imgur.com/mINvWzm.png)

![](https://i.imgur.com/FQZNevn.png)

![](https://i.imgur.com/da2i6KC.png)

![](https://i.imgur.com/dVpu77h.png)

![](https://i.imgur.com/ufUIc8D.png)
```yml=
#kibana.yml

server.port: 5601
server.host: "192.168.112.90"
elasticsearch.hosts: ["https://192.168.112.90:9200"]
kibana.index: ".kibana"
elasticsearch.username: "elastic"
elasticsearch.password: "1qaz@WSX"
server.ssl.enabled: true
server.ssl.certificate: /apdatas/opt/kibana/kibana-7.17.7-linux-x86_64/config/kibana-server.crt
server.ssl.key: /apdatas/opt/kibana/kibana-7.17.7-linux-x86_64/config/kibana-server.key
elasticsearch.ssl.certificate: /apdatas/opt/kibana/kibana-7.17.7-linux-x86_64/config/client.cer
elasticsearch.ssl.key: /apdatas/opt/kibana/kibana-7.17.7-linux-x86_64/config/client.key
xpack.security.enabled: true
elasticsearch.ssl.certificateAuthorities: [ "/apdatas/opt/kibana/kibana-7.17.7-linux-x86_64/config/elasticsearch-ca.pem" ]
elasticsearch.ssl.verificationMode: certificate
pid.file: /apdatas/opt/kibana/kibana-7.17.7-linux-x86_64/config/kibana.pid
i18n.locale: "en"
xpack.encryptedSavedObjects.encryptionKey: 3cc5eea705e4649b91dca4c0731c8687
xpack.reporting.encryptionKey: ed3123e067a6ddd4263aeba27d1e9108
xpack.security.encryptionKey: 68c5e3c908cf72d9f6a5d2083757082c
server.securityResponseHeaders.strictTransportSecurity: "max-age=31536000"
server.securityResponseHeaders.disableEmbedding: true
csp.strict: true 
```

* 憑證以及kibana.yml檔案均準備好之後，即可啟動。
```shell=
#啟動測試
bin/kibana
```
![](https://i.imgur.com/abIyn8n.png)
```shell=
#背景執行
nohup bin/kibana >/dev/null 2>&1
```
![](https://i.imgur.com/wWJjw7O.png)
* 使用terminal測試
```shell=
curl -k -v -u elastic -XGET https://192.168.112.90:5601/app/login
```
![](https://i.imgur.com/BSIRfAg.png)
![](https://i.imgur.com/mUcYPBh.png)
![](https://i.imgur.com/d54ftNL.png)
![](https://i.imgur.com/jGXPkEQ.png)
![](https://i.imgur.com/g38VIKf.png)


* 使用browser登入
![](https://i.imgur.com/6MKOHiB.png)

![](https://i.imgur.com/3quayt1.png)

![](https://i.imgur.com/UnC2QUE.png)

![](https://i.imgur.com/LMvq4wa.png)
* **Kibana安裝完成，並與Elasticseach連線正常**
---
### PROMETHEUS、GRAFANA
#### PROMETHEUS
* 準備憑證
```shell=
cd /apdatas/tls_dir/prometheus_tls/

openssl req -newkey rsa:4096 -nodes -sha256 -keyout prometheus.key -out prometheus.csr -subj "/C=TW/ST=Taiwan/L=Taiwan/O=Pershiung/OU=DFU/CN=192.168.112.86/CN=192.168.112.87/CN=192.168.112.88/CN=192.168.112.90/CN=192.168.112.91/CN=192.168.112.92/emailAddress=ptsc@gmail.com"
```
![](https://i.imgur.com/Eia6BV1.png)

```shell=
#擴展名使用的檔案
cat > v3.ext <<-EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth,clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1=pibmid01
DNS.2=pibmid02
DNS.3=pibmid03
DNS.4=localhost
DNS.5=pibagt01
DNS.6=pibagt02
DNS.7=pibagt03
IP.1 =192.168.112.90
IP.2 =192.168.112.91
IP.3 =192.168.112.92
IP.4 =192.168.112.86
IP.5 =192.168.112.87
IP.6 =192.168.112.88
IP.7 =127.0.0.1
EOF

#用前面安裝kafka時，產出的ca.key、ca.crt簽屬prometheus.csr
openssl x509 -req -days 3650 -in prometheus.csr -CA /apdatas/tls_dir/kafka_tls/ca.crt -CAkey /apdatas/tls_dir/kafka_tls/ca.key -CAcreateserial -extfile v3.ext -out prometheus.cert
```
![](https://i.imgur.com/Zi71ix6.png)

* 將prometheus安裝檔解壓縮至/apdatas/opt/prometheus/，到資料夾下調整設定檔
* 修改prometheus.yml
```shell=
tar zxvf prometheus-2.37.5.linux-amd64.tar.gz -C /apdatas/opt/prometheus/

cd /apdatas/opt/prometheus/prometheus-2.37.5.linux-amd64/
```
![](https://i.imgur.com/OC0zXu0.png)
![](https://i.imgur.com/57sBJQ8.png)
```shell=
vim prometheus.yml
```
```yml=
#prometheus.yml
global:
rule_files:
  - "prometheus-rules.yml"
  - "rke2-cluster-rules.yml"
scrape_configs:
  - job_name: "prometheus"
    tls_config:
      ca_file: /apdatas/tls_dir/kafka_tls/ca.crt
      cert_file: /apdatas/tls_dir/prometheus_tls/prometheus.cert
      key_file: /apdatas/tls_dir/prometheus_tls/prometheus.key
      insecure_skip_verify: true
    scheme: https
    static_configs:
      - targets: ["192.168.112.90:9090","192.168.112.91:9090","192.168.112.92:9090"]
  - job_name: "rke2-cluster"
    scheme: https
    tls_config:
      ca_file: /apdatas/tls_dir/kafka_tls/ca.crt
      cert_file: /apdatas/tls_dir/prometheus_tls/prometheus.cert
      key_file: /apdatas/tls_dir/prometheus_tls/prometheus.key
      insecure_skip_verify: true
    static_configs:
      - targets: ["192.168.112.86:9100","192.168.112.87:9100","192.168.112.88:9100"]

```
![](https://i.imgur.com/xK6yv7W.png)
* 建立certificate_config.yml
```shell=
cat > certificate_config.yml<<EOF
tls_server_config:
  cert_file: /apdatas/tls_dir/prometheus_tls/prometheus.cert
  key_file: /apdatas/tls_dir/prometheus_tls/prometheus.key
EOF
```
![](https://i.imgur.com/isVGvmq.png)
* 建立prometheus-rules.yml
```shell=
cat >prometheus-rules.yml<<EOF
groups:
  - name: prometheus-rules
    rules:
      #cpu resource inspect
      - record: instance:process_cpu_seconds_total:avg_rate
        expr: avg(rate(process_cpu_seconds_total[5m]))by(instance)
        labels:
          job: prometheus-resource-avg
      #memory resource inspect
      - record: instance:node_cpu_seconds_total:avg_rate
        expr: (1-avg(irate(node_cpu_seconds_total{job="rke2-cluster",mode="idle"}[5m]))by(instance))*100
        labels:
          job: rke2-cluster-resource-avg
      - record: instance:node_memory_MemTotal_bytes:avg
        expr: avg((node_memory_MemTotal_bytes{job="rke2-cluster"}-node_memory_MemAvailable_bytes{job="rke2-cluster"})/node_memory_MemTotal_bytes{job="rke2-cluster"}) by(instance)
        labels:
          job: rke2-cluster-resource-avg
      #memory resource inspect
      - record: instance:node_memory_MemTotal_bytes
        expr: 100 - ((node_memory_MemFree_bytes{instance="192.168.112.86:9100"}+node_memory_Cached_bytes{instance="192.168.112.86:9100"}+node_memory_Buffers_bytes{instance="192.168.112.86:9100"})/node_memory_MemTotal_bytes) * 100
        labels:
          job: rke2-cluster-mem-active
      - record: instance:node_memory_MemTotal_bytes
        expr: 100 - ((node_memory_MemFree_bytes{instance="192.168.112.87:9100"}+node_memory_Cached_bytes{instance="192.168.112.87:9100"}+node_memory_Buffers_bytes{instance="192.168.112.87:9100"})/node_memory_MemTotal_bytes) * 100
        labels:
          job: rke2-cluster-mem-active
      - record: instance:node_memory_MemTotal_bytes
        expr: 100 - ((node_memory_MemFree_bytes{instance="192.168.112.88:9100"}+node_memory_Cached_bytes{instance="192.168.112.88:9100"}+node_memory_Buffers_bytes{instance="192.168.112.88:9100"})/node_memory_MemTotal_bytes) * 100
        labels:
          job: rke2-cluster-mem-active
      #storage resource inspect
      - record: instance:node_filesystem_size_bytes:sum
        expr: sum(100 - node_filesystem_free_bytes{fstype!~"rootfs|selinuxfs|autofs|rpc_pipefs|tmpfs|udev|none|devpts|sysfs|debugfs|fuse.*"} / node_filesystem_size_bytes{fstype!~"rootfs|selinuxfs|autofs|rpc_pipefs|tmpfs|udev|none|devpts|sysfs|debugfs|fuse.*"} * 100 )by (instance) 
        labels:
          job: rke2-cluster-storage-active
      #internet IO inspect
      - record: instance:node_network_receive_bytes_total:sum_rate_lo
        expr: sum(rate(node_network_receive_bytes_total{device!="lo"}[5m]))by (instance)
        labels:
          job: rke2-cluster-internet-lo-input
      - record: instance:node_network_transmit_bytes_total:sum_rate_lo
        expr: sum(rate(node_network_transmit_bytes_total{device!="lo"}[5m]))by (instance) 
        labels:
          job: rke2-cluster-internet-lo-output
      #internet 
      - record: instance:node_network_receive_bytes_total:sum_rate_both
        expr: sum(irate(node_network_receive_bytes_total{device!~"bond.*?|lo"}[5m])/128)by (instance) 
        labels:
          job: rke2-cluster-internet-both-input
      - record: instance:node_network_transmit_bytes_total:sum_rate_both
        expr: sum(irate(node_network_transmit_bytes_total{device!~"bond.*?|lo"}[5m])/128)by (instance) 
        labels:
                job: rke2-cluster-internet-both-output
EOF
```
* 建立rke2-cluster-rules.yml
```shell=
cat >rke2-cluster-rules.yml<<EOF
groups:
  - name: rke2-cluster-alert-rules
    rules:
    - alert: HighRequestLatency
      expr: job:request_latency_seconds:mean5m{job="rke2-cluster"} > 0.5
      for: 5m
      labels:
        severity: page
      annotations:
        summary: "High request on {{ $labels.instance }} latency"
    - alert: InstanceCantConnect
      expr: device:node_network_up{device="ens33"} < 1
      for: 5m
      labels:
        severity: page
      annotations:
        summary: "Instance {{ $labels.instance }} can't connect! "
        description: "{{ $labels.instance }}"
    - alert: PrometheusBadConfig
      annotations:
        description: Prometheus {{$labels.instance}} has failed to
          reload its configuration.
        runbook_url: https://runbooks.prometheus-operator.dev/runbooks/prometheus/prometheusbadconfig
        summary: Failed Prometheus configuration reload.
      expr: |
        max_over_time(prometheus_config_last_reload_successful{job="prometheus"}[5m]) == 0
      for: 10m
      labels:
        severity: critical
    - alert: PrometheusNotificationQueueRunningFull
      annotations:
        description: Alert notification queue of Prometheus {{$labels.instance}}
          is running full.
        runbook_url: https://runbooks.prometheus-operator.dev/runbooks/prometheus/prometheusnotificationqueuerunningfull
        summary: Prometheus alert notification queue predicted to run full in less
          than 30m.
      expr: |
        (
          predict_linear(prometheus_notifications_queue_length{job="prometheus"}[5m], 60 * 30)
        >
          min_over_time(prometheus_notifications_queue_capacity{job="prometheus"}[5m])
        )
      for: 15m
      labels:
        severity: warning
    - alert: PrometheusErrorSendingAlertsToSomeAlertmanagers
      annotations:
        description: '{{ printf "%.1f" $value }}% errors while sending alerts from
          Prometheus {{$labels.instance}} to Alertmanager {{$labels.alertmanager}}.'
        runbook_url: https://runbooks.prometheus-operator.dev/runbooks/prometheus/prometheuserrorsendingalertstosomealertmanagers
        summary: Prometheus has encountered more than 1% errors sending alerts to
          a specific Alertmanager.
      expr: |
        (
          rate(prometheus_notifications_errors_total{job="prometheus"}[5m])
        /
          rate(prometheus_notifications_sent_total{job="prometheus"}[5m])
        )
        * 100
        > 1
      for: 15m
      labels:
        severity: warning
    - alert: PrometheusNotConnectedToAlertmanagers
      annotations:
        description: Prometheus {{$labels.instance}} is not connected
          to any Alertmanagers.
        runbook_url: https://runbooks.prometheus-operator.dev/runbooks/prometheus/prometheusnotconnectedtoalertmanagers
        summary: Prometheus is not connected to any Alertmanagers.
      expr: |
        max_over_time(prometheus_notifications_alertmanagers_discovered{job="prometheus"}[5m]) < 1
      for: 10m
      labels:
        severity: warning
    - alert: PrometheusTSDBReloadsFailing
      annotations:
        description: Prometheus {{$labels.instance}} has detected
          {{$value | humanize}} reload failures over the last 3h.
        runbook_url: https://runbooks.prometheus-operator.dev/runbooks/prometheus/prometheustsdbreloadsfailing
        summary: Prometheus has issues reloading blocks from disk.
      expr: |
        increase(prometheus_tsdb_reloads_failures_total{job="prometheus"}[3h]) > 0
      for: 4h
      labels:
        severity: warning
    - alert: PrometheusTSDBCompactionsFailing
      annotations:
        description: Prometheus {{$labels.instance}} has detected
          {{$value | humanize}} compaction failures over the last 3h.
        runbook_url: https://runbooks.prometheus-operator.dev/runbooks/prometheus/prometheustsdbcompactionsfailing
        summary: Prometheus has issues compacting blocks.
      expr: |
        increase(prometheus_tsdb_compactions_failed_total{job="prometheus"}[3h]) > 0
      for: 4h
      labels:
        severity: warning
    - alert: PrometheusNotIngestingSamples
      annotations:
        description: Prometheus {{$labels.instance}} is not ingesting
          samples.
        runbook_url: https://runbooks.prometheus-operator.dev/runbooks/prometheus/prometheusnotingestingsamples
        summary: Prometheus is not ingesting samples.
      expr: |
        (
          rate(prometheus_tsdb_head_samples_appended_total{job="prometheus"}[5m]) <= 0
        and
          (
            sum without(scrape_job) (prometheus_target_metadata_cache_entries{job="prometheus"}) > 0
          or
            sum without(rule_group) (prometheus_rule_group_rules{job="prometheus"}) > 0
          )
        )
      for: 10m
      labels:
        severity: warning
    - alert: PrometheusDuplicateTimestamps
      annotations:
        description: Prometheus {{$labels.instance}} is dropping
          {{ printf "%.4g" $value  }} samples/s with different values but duplicated
          timestamp.
        runbook_url: https://runbooks.prometheus-operator.dev/runbooks/prometheus/prometheusduplicatetimestamps
        summary: Prometheus is dropping samples with duplicate timestamps.
      expr: |
        rate(prometheus_target_scrapes_sample_duplicate_timestamp_total{job="prometheus"}[5m]) > 0
      for: 10m
      labels:
        severity: warning
    - alert: PrometheusOutOfOrderTimestamps
      annotations:
        description: Prometheus {{$labels.instance}} is dropping
          {{ printf "%.4g" $value  }} samples/s with timestamps arriving out of order.
        runbook_url: https://runbooks.prometheus-operator.dev/runbooks/prometheus/prometheusoutofordertimestamps
        summary: Prometheus drops samples with out-of-order timestamps.
      expr: |
        rate(prometheus_target_scrapes_sample_out_of_order_total{job="prometheus"}[5m]) > 0
      for: 10m
      labels:
        severity: warning
    - alert: PrometheusRemoteStorageFailures
      annotations:
        description: Prometheus {{$labels.instance}} failed to send
          {{ printf "%.1f" $value }}% of the samples to {{ $labels.remote_name}}:{{
          $labels.url }}
        runbook_url: https://runbooks.prometheus-operator.dev/runbooks/prometheus/prometheusremotestoragefailures
        summary: Prometheus fails to send samples to remote storage.
      expr: |
        (
          (rate(prometheus_remote_storage_failed_samples_total{job="prometheus"}[5m]) or rate(prometheus_remote_storage_samples_failed_total{job="prometheus"}[5m]))
          /
          (
            (rate(prometheus_remote_storage_failed_samples_total{job="prometheus"}[5m]) or rate(prometheus_remote_storage_samples_failed_total{job="prometheus"}[5m]))
          +
            (rate(prometheus_remote_storage_succeeded_samples_total{job="prometheus"}[5m]) or rate(prometheus_remote_storage_samples_total{job="prometheus"}[5m]))
          )
        )
        * 100
        > 1
      for: 15m
      labels:
        severity: critical
    - alert: PrometheusRemoteWriteBehind
      annotations:
        description: Prometheus {{$labels.instance}} remote write
          is {{ printf "%.1f" $value }}s behind for {{ $labels.remote_name}}:{{ $labels.url
          }}.
        runbook_url: https://runbooks.prometheus-operator.dev/runbooks/prometheus/prometheusremotewritebehind
        summary: Prometheus remote write is behind.
      expr: |
        (
          max_over_time(prometheus_remote_storage_highest_timestamp_in_seconds{job="prometheus"}[5m])
        - ignoring(remote_name, url) group_right
          max_over_time(prometheus_remote_storage_queue_highest_sent_timestamp_seconds{job="prometheus"}[5m])
        )
        > 120
      for: 15m
      labels:
        severity: critical
    - alert: PrometheusRemoteWriteDesiredShards
      annotations:
        description: Prometheus {{$labels.instance}} remote write
          desired shards calculation wants to run {{ $value }} shards for queue {{
          $labels.remote_name}}:{{ $labels.url }}, which is more than the max of {{
          printf `prometheus_remote_storage_shards_max{instance="%s",job="prometheus"}`
          $labels.instance | query | first | value }}.
        runbook_url: https://runbooks.prometheus-operator.dev/runbooks/prometheus/prometheusremotewritedesiredshards
        summary: Prometheus remote write desired shards calculation wants to run more
          than configured max shards.
      expr: |
        (
          max_over_time(prometheus_remote_storage_shards_desired{job="prometheus"}[5m])
        >
          max_over_time(prometheus_remote_storage_shards_max{job="prometheus"}[5m])
        )
      for: 15m
      labels:
        severity: warning
    - alert: PrometheusRuleFailures
      annotations:
        description: Prometheus {{$labels.instance}} has failed to
          evaluate {{ printf "%.0f" $value }} rules in the last 5m.
        runbook_url: https://runbooks.prometheus-operator.dev/runbooks/prometheus/prometheusrulefailures
        summary: Prometheus is failing rule evaluations.
      expr: |
        increase(prometheus_rule_evaluation_failures_total{job="prometheus"}[5m]) > 0
      for: 15m
      labels:
        severity: critical
    - alert: PrometheusMissingRuleEvaluations
      annotations:
        description: Prometheus {{$labels.instance}} has missed {{
          printf "%.0f" $value }} rule group evaluations in the last 5m.
        runbook_url: https://runbooks.prometheus-operator.dev/runbooks/prometheus/prometheusmissingruleevaluations
        summary: Prometheus is missing rule evaluations due to slow rule group evaluation.
      expr: |
        increase(prometheus_rule_group_iterations_missed_total{job="prometheus"}[5m]) > 0
      for: 15m
      labels:
        severity: warning
    - alert: PrometheusTargetLimitHit
      annotations:
        description: Prometheus {{$labels.instance}} has dropped
          {{ printf "%.0f" $value }} targets because the number of targets exceeded
          the configured target_limit.
        runbook_url: https://runbooks.prometheus-operator.dev/runbooks/prometheus/prometheustargetlimithit
        summary: Prometheus has dropped targets because some scrape configs have exceeded
          the targets limit.
      expr: |
        increase(prometheus_target_scrape_pool_exceeded_target_limit_total{job="prometheus"}[5m]) > 0
      for: 15m
      labels:
        severity: warning
    - alert: PrometheusLabelLimitHit
      annotations:
        description: Prometheus {{$labels.instance}} has dropped
          {{ printf "%.0f" $value }} targets because some samples exceeded the configured
          label_limit, label_name_length_limit or label_value_length_limit.
        runbook_url: https://runbooks.prometheus-operator.dev/runbooks/prometheus/prometheuslabellimithit
        summary: Prometheus has dropped targets because some scrape configs have exceeded
          the labels limit.
      expr: |
        increase(prometheus_target_scrape_pool_exceeded_label_limits_total{job="prometheus"}[5m]) > 0
      for: 15m
      labels:
        severity: warning
    - alert: PrometheusScrapeBodySizeLimitHit
      annotations:
        description: Prometheus {{$labels.instance}} has failed {{
          printf "%.0f" $value }} scrapes in the last 5m because some targets exceeded
          the configured body_size_limit.
        runbook_url: https://runbooks.prometheus-operator.dev/runbooks/prometheus/prometheusscrapebodysizelimithit
        summary: Prometheus has dropped some targets that exceeded body size limit.
      expr: |
        increase(prometheus_target_scrapes_exceeded_body_size_limit_total{job="prometheus"}[5m]) > 0
      for: 15m
      labels:
        severity: warning
    - alert: PrometheusScrapeSampleLimitHit
      annotations:
        description: Prometheus {{$labels.instance}} has failed {{
          printf "%.0f" $value }} scrapes in the last 5m because some targets exceeded
          the configured sample_limit.
        runbook_url: https://runbooks.prometheus-operator.dev/runbooks/prometheus/prometheusscrapesamplelimithit
        summary: Prometheus has failed scrapes that have exceeded the configured sample
          limit.
      expr: |
        increase(prometheus_target_scrapes_exceeded_sample_limit_total{job="prometheus"}[5m]) > 0
      for: 15m
      labels:
        severity: warning
    - alert: PrometheusTargetSyncFailure
      annotations:
        description: '{{ printf "%.0f" $value }} targets in Prometheus {{$labels.instance}}
          have failed to sync because invalid configuration was supplied.'
        runbook_url: https://runbooks.prometheus-operator.dev/runbooks/prometheus/prometheustargetsyncfailure
        summary: Prometheus has failed to sync targets.
      expr: |
        increase(prometheus_target_sync_failed_total{job="prometheus"}[30m]) > 0
      for: 5m
      labels:
        severity: critical
    - alert: PrometheusHighQueryLoad
      annotations:
        description: Prometheus {{$labels.instance}} query API has
          less than 20% available capacity in its query engine for the last 15 minutes.
        runbook_url: https://runbooks.prometheus-operator.dev/runbooks/prometheus/prometheushighqueryload
        summary: Prometheus is reaching its maximum capacity serving concurrent requests.
      expr: |
        avg_over_time(prometheus_engine_queries{job="prometheus"}[5m]) / max_over_time(prometheus_engine_queries_concurrent_max{job="prometheus"}[5m]) > 0.8
      for: 15m
      labels:
        severity: warning
    - alert: PrometheusErrorSendingAlertsToAnyAlertmanager
      annotations:
        description: '{{ printf "%.1f" $value }}% minimum errors while sending alerts
          from Prometheus {{$labels.instance}} to any Alertmanager.'
        runbook_url: https://runbooks.prometheus-operator.dev/runbooks/prometheus/prometheuserrorsendingalertstoanyalertmanager
        summary: Prometheus encounters more than 3% errors sending alerts to any Alertmanager.
      expr: |
        min without (alertmanager) (
          rate(prometheus_notifications_errors_total{job="prometheus",alertmanager!~``}[5m])
        /
          rate(prometheus_notifications_sent_total{job="prometheus",alertmanager!~``}[5m])
        )
        * 100
        > 3
      for: 15m
      labels:
        severity: critical

EOF
```
```shell=
#查看目前資料夾的檔案是否存在
ll
```
![](https://i.imgur.com/EHoz6Lb.png)

```shell=
#準備完成後，啟動prometheus指令
./prometheus --web.config.file=./certificate_config.yml

#背景執行指令
nohup ./prometheus --web.config.file=./certificate_config.yml >/dev/null 2>&1
```
![](https://i.imgur.com/rcSTtj1.png)

* teminal測試
```shell=
curl -k https://192.168.112.90:9090
```
![](https://i.imgur.com/6jisyEQ.png)
* 網頁登入
![](https://i.imgur.com/0aWrGOW.png)
* 僅啟動第一台，可以看到up為正常，第一台安裝完成。
![](https://i.imgur.com/Pgpw8vx.png)
* 點連結可以看到資料，代表連接成功。
![](https://i.imgur.com/Rj1NeYT.png)

* 將prometheus.key以及prometheus.cert複製給另外兩台安裝prometheus的機器，並以相同步驟設定config檔案即可完成安裝。


#### Grafana
* 將安裝檔解壓縮至/apdatas/opt/grafana/
```shell=
 tar zxvf grafana-9.3.6.tar.gz -C /apdatas/opt/grafana/
 cd /apdatas/opt/grafana/grafana-9.3.6/
```
![](https://i.imgur.com/FFrKxKy.png)
![](https://i.imgur.com/hZ1ty3o.png)


* 修改config/default.ini
![](https://i.imgur.com/UTNG919.png)
![](https://i.imgur.com/RXAH17u.png)
![](https://i.imgur.com/czHwAyO.png)
![](https://i.imgur.com/g5CcQDh.png)


* 瀏覽器登入(首次登入若使用自訂的帳號無法登入，就使用預設帳號admin登入，密碼即為default.ini中自訂的密碼(這裡自訂密碼:1qaz@WSX)
![](https://i.imgur.com/R7jKdqt.png)
![](https://i.imgur.com/jYI9dsz.png)
![](https://i.imgur.com/D5cxP7t.png)
![](https://i.imgur.com/g3tu2bk.png)
![](https://i.imgur.com/vDVJtk4.png)
![](https://i.imgur.com/sW6GZpf.png)

![](https://i.imgur.com/EO4ZGQt.png)
![](https://i.imgur.com/4Qhtb3N.png)
![](https://i.imgur.com/f8gXCX8.png)

* 確認已經將grafana與prometheus完成連接，後續依相同步驟在data source加入第二台即第三台prometheus即可讀取到另外兩台的資料。
---
