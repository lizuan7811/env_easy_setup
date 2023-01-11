#!/bin/bash

echo '產TLS key步驟'
echo '***********************DOCKER、HARBOR**********************************'
#產Docker、Harbor使用的TLS
openssl req \
    -newkey rsa:4096 -nodes -sha256 -keyout ca.key \
    -x509 -days 3650 -out ca.crt \
    -subj "/C=TW/ST=Taiwan/L=Taiwan/O=Pershiung/OU=TDU/CN=172.168.113.110/CN=172.168.113.107/CN=172.168.113.108/CN=172.168.113.109/emailAddress=tnibmid@gmail.com"
	
openssl req \
    -newkey rsa:4096 -nodes -sha256 -keyout harbor-registry.key \
    -out harbor-registry.csr \
    -subj "/C=TW/ST=Taiwan/L=Taiwan/O=Pershiung/OU=TDU/CN=172.168.113.110/CN=172.168.113.107/CN=172.168.113.108/CN=172.168.113.109/emailAddress=tnibmid@gmail.com"


cat > v3.ext <<-EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1=k8s1
DNS.2=k8s2
DNS.3=k8s3
DNS.4=kafka1
DNS.5=kafka2
DNS.6=kafka3
IP.1 =172.168.113.108
IP.2 =172.168.113.109
IP.3 =172.168.113.110
IP.4 =172.168.113.111
IP.5 =172.168.113.112
IP.6 =172.168.113.113
IP.7 =127.0.0.1

EOF

#若有多個Client需要連接，就需要寫入多個IP。
#ectAltName = IP:172.168.113.110 > extfile.cnf 
#簽發自簽證書
openssl x509 -req -days 365 -in harbor-registry.csr -CA ca.crt -CAkey ca.key -CAcreateserial -extfile v3.ext -out harbor-registry.crt
#docker需要PEM格式的證書，所以將自簽證書轉為PEM格式
openssl x509 -inform PEM -in harbor-registry.crt -out harbor-registry.cert
echo '***********************DOCKER、HARBOR**********************************'

echo '***********************KAFKA*******************************************'
openssl genrsa -out kafka-ca.key 4096
openssl req -new -x509 -key kafka-ca.key -out kafka-ca.crt -subj "/C=TW/ST=Taiwan/L=Taiwan/O=Pershiung/OU=TDU/CN=172.168.113.110/CN=172.168.113.107/CN=172.168.113.108/CN=172.168.113.109/emailAddress=tnibmid@gmail.com"
chmod 600 kafka-ca.key
chmod 644 kafka-ca.crt

#將kafka-ca.crt加入至kafka.truststore.jks中
keytool -keystore kafka.truststore.jks -alias CARoot -import -file kafka-ca.crt
#產一個儲存在kafka1.keystore.jks中的Key(key輸出的副檔名為.crt)
keytool -keystore kafka1.keystore.jks -alias 172.168.113.110 -validity 3650 -genkey -keyalg RSA -ext SAN=DNS:rke2-server4
#將存在kafka1.keystore.jks中，alias為172.168.113.107的key輸出為kafka1.unsigned.crt(未經簽發)
keytool -keystore kafka1.keystore.jks -alias 172.168.113.110 -certreq -file kafka1.unsigned.crt
#簽發證書(會輸入有效期限)，將未經簽發的證書輸入執行簽發，並產出kafka.signed.crt
openssl x509 -req -CA kafka-ca.crt -CAkey kafka-ca.key -in kafka1.unsigned.crt -out kafka1.signed.crt -days 3650 -CAcreateserial
#將kafka-ca.crt匯入kafka.keystore.jks中，標記為CARoot的值。
keytool -keystore kafka1.keystore.jks -alias CARoot -import -file kafka-ca.crt
#替換存在kafka1.keystore.jks中，儲存在alias為172.168.113.107的key，換為經簽發的kafka1.signed.crt證書
keytool -keystore kafka1.keystore.jks -alias 172.168.113.110 -import -file kafka1.signed.crt
#若尚未將憑證傳給kafka1，可使用下列指令複製過去
#scp kafka.truststore.jks kafka1.keystore.jks root@kafka

echo '***********************Elasticsearch、Kibana***************************'



#xpack.security.enabled: true
#discovery.type: single-node
#./bin/elasticsearch
#./bin/elasticsearch-setup-passwords auto
#./bin/elasticsearch-setup-passwords interactive

elasticsearch.username: "kibana_system"
./bin/kibana-keystore create

#./bin/kibana-keystore add elasticsearch.password

#./bin/kibana

./bin/elasticsearch-certutil ca
./bin/elasticsearch-certutil cert --ca elastic-stack-ca.p12
./bin/elasticsearch-certutil http

#cluster.name: my-cluster
#node.name: node-1
#xpack.security.transport.ssl.enabled: true
#xpack.security.transport.ssl.verification_mode: certificate 
#xpack.security.transport.ssl.client_authentication: required
#xpack.security.transport.ssl.keystore.path: elastic-certificates.p12
#xpack.security.transport.ssl.truststore.path: elastic-certificates.p12

#./bin/elasticsearch-keystore add xpack.security.transport.ssl.keystore.secure_password

#./bin/elasticsearch-keystore add xpack.security.transport.ssl.truststore.secure_password





elasticsearch.ssl.certificateAuthorities: $KBN_PATH_CONF/elasticsearch-ca.pem
elasticsearch.hosts: https://<your_elasticsearch_host>:9200

./bin/elasticsearch-certutil csr -name kibana-server -dns rke2-server4
server.ssl.certificate: $KBN_PATH_CONF/kibana-server.crt
server.ssl.key: $KBN_PATH_CONF/kibana-server.key

server.ssl.enabled: true



#kibana config設定時，會用到cer及key。直接從elasticsearch util產出的http.p12轉出來使用。
openssl pkcs12 -in http.p12 -nocerts -nodes  > client.key
openssl pkcs12 -in http.p12 -clcerts -nokeys  > client.cer


#按造步驟產生key之後，使用kafka-connect連elasticsearch時，需先將elastic-certificates.p12匯入系統根憑證儲存的地方。
keytool -importkeystore -deststorepass changeit -destkeystore /etc/pki/ca-trust/extracted/java/cacerts -srckeystore elastic/config/elastic-certificates.p12 -srcstoretype pkcs12
curl -XPOST "http://172.168.113.110:8083/connectors" -H 'Content-Type: application/json' -d'
{
  "name": "connect-channel",
  "config": {
   "topics": "connect-channell",
   "connector.class": "io.confluent.connect.elasticsearch.ElasticsearchSinkConnector",
   "connection.username": "elastic",
   "connection.password": "Admin@@@111",
   "connection.url": "https://172.168.113.110:9200",
   "tasks.max": "1"
 }
}'