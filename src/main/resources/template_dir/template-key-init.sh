#!/bin/bash
echo '產TLS key步驟'
echo '***********************DOCKER、HARBOR**********************************'
#產Docker、Harbor使用的TLS
echo "Harbor 使用的憑證"
openssl req -newkey rsa:4096 -nodes -sha256 -keyout ${HARBOR_CA_NAME}.key -x509 -days 3650 -out ${HARBOR_CA_NAME}.crt -subj ${HARBOR_SUBJ}
openssl req -newkey rsa:4096 -nodes -sha256 -keyout ${HARBOR_SERVER}.key -out ${HARBOR_SERVER}.csr -subj ${HARBOR_SUBJ}
#"/C=TW/ST=Taiwan/L=Taiwan/O=Pershiung/OU=TDU/CN=172.168.113.110/CN=172.168.113.107/CN=172.168.113.108/CN=172.168.113.109/emailAddress=tnibmid@gmail.com"
#若有多個Client需要連接，就需要寫入多個IP。
#ectAltName = IP:172.168.113.110 > extfile.cnf 
#簽發自簽證書
echo "Docker 使用的憑證"
openssl x509 -req -days ${VALIDITY_DAY} -in ${HARBOR_SERVER}.csr -CA ${HARBOR_CA_NAME}.crt -CAkey ${HARBOR_CA_NAME}.key -CAcreateserial -extfile ${V3_FILE_NAME} -out ${HARBOR_SERVER}.crt
#docker需要PEM格式的證書，所以將自簽證書轉為PEM格式
openssl x509 -inform PEM -in ${HARBOR_SERVER}.crt -out ${HARBOR_SERVER}.cert
echo '***********************DOCKER、HARBOR**********************************'
echo '***********************KAFKA*******************************************'
openssl genrsa -out ${KAFKA_CA_NAME}.key 4096
openssl req -new -x509 -key ${KAFKA_CA_NAME}.key -out ${KAFKA_CA_NAME}.crt -subj ${KAFKA_SUBJ} #"/C=TW/ST=Taiwan/L=Taiwan/O=Pershiung/OU=TDU/CN=172.168.113.110/CN=172.168.113.107/CN=172.168.113.108/CN=172.168.113.109/emailAddress=tnibmid@gmail.com"
chmod 600 ${KAFKA_CA_NAME}.key
chmod 644 ${KAFKA_CA_NAME}.crt

# keytool -genkey -alias test-key -keypass Admin@@@111 -keyalg RSA -keysize 4096 -validity 3650 -keystore test-key.keystore -storepass Admin@@@111 -dname 'C=TW,ST=Taiwan,L=Taiwan,O=Pershiung,OU=TDU,CN=172.168.113.110,CN=172.168.113.107,CN=172.168.113.108,CN=172.168.113.109,emailAddress=tnibmid@gmail.com'
#將kafka-ca.crt加入至kafka.truststore.jks中
keytool -keystore ${KAFKA_STORE_NAME}.truststore.jks -alias ${KAFKA_TRUSTSTORE_ALIAS} -import -file ${KAFKA_CA_NAME}.crt
#產一個儲存在kafka1.keystore.jks中的Key(key輸出的副檔名為.crt)
keytool -keystore ${KAFKA_STORE_NAME}.keystore.jks -alias ${KAFKA_KEYTSTORE_ALIAS} -validity ${VALIDITY_DAY} -genkey -keyalg RSA -ext SAN=DNS:DNS_NAME}}
#將存在kafka1.keystore.jks中，alias為172.168.113.107的key輸出為kafka1.unsigned.crt(未經簽發)
keytool -keystore kafka1.keystore.jks -alias 172.168.113.110 -certreq -file kafka1.unsigned.crt
#簽發證書(會輸入有效期限)，將未經簽發的證書輸入執行簽發，並產出kafka.signed.crt
openssl x509 -req -CA ${KAFKA_CA_NAME}.crt -CAkey ${KAFKA_CA_NAME}.key -in kafka.unsigned.crt -out kafka.signed.crt -days 3650 -CAcreateserial
#將kafka-ca.crt匯入kafka.keystore.jks中，標記為CARoot的值。
keytool -keystore ${KAFKA_STORE_NAME}.keystore.jks -alias ${KAFKA_KEYSTORE_ALIAS} -import -file ${KAFKA_CA_NAME}.crt
#替換存在kafka1.keystore.jks中，儲存在alias為172.168.113.107的key，換為經簽發的kafka1.signed.crt證書
keytool -keystore ${KAFKA_STORE_NAME}.keystore.jks -alias ${KAFKA_KEYSTORE_ALIAS} -import -file kafka.signed.crt
#若尚未將憑證傳給kafka1，可使用下列指令複製過去
#scp kafka.truststore.jks kafka1.keystore.jks root@kafka
#'C=TW,ST=Taiwan,L=Taiwan,O=Pershiung,OU=TDU,CN=172.168.113.110,CN=172.168.113.107,CN=172.168.113.108,CN=172.168.113.109,emailAddress=tnibmid@gmail.com'
echo '***********************Elasticsearch、Kibana***************************'
#xpack.security.enabled: true
#discovery.type: single-node
#./bin/elasticsearch
#./bin/elasticsearch-setup-passwords auto
#./bin/elasticsearch-setup-passwords interactive

#elasticsearch.username: "kibana_system"
#./bin/kibana-keystore create
#./bin/kibana-keystore add elasticsearch.password
#./bin/kibana
#./bin/elasticsearch-certutil ca
#./bin/elasticsearch-certutil cert --ca elastic-stack-ca.p12
#./bin/elasticsearch-certutil http
#cluster.name: my-cluster
#node.name: node-1
#xpack.security.transport.ssl.enabled: true
#xpack.security.transport.ssl.verification_mode: certificate 
#xpack.security.transport.ssl.client_authentication: required
#xpack.security.transport.ssl.keystore.path: elastic-certificates.p12
#xpack.security.transport.ssl.truststore.path: elastic-certificates.p12
#./bin/elasticsearch-keystore add xpack.security.transport.ssl.keystore.secure_password
#./bin/elasticsearch-keystore add xpack.security.transport.ssl.truststore.secure_password
#elasticsearch.ssl.certificateAuthorities: $KBN_PATH_CONF/elasticsearch-ca.pem
#elasticsearch.hosts: https://<your_elasticsearch_host>:9200
#./bin/elasticsearch-certutil csr -name kibana-server -dns rke2-server4
#server.ssl.certificate: $KBN_PATH_CONF/kibana-server.crt
#server.ssl.key: $KBN_PATH_CONF/kibana-server.key
#server.ssl.enabled: true
#kibana config設定時，會用到cer及key。直接從elasticsearch util產出的http.p12轉出來使用。
#openssl pkcs12 -in http.p12 -nocerts -nodes  > client.key
#openssl pkcs12 -in http.p12 -clcerts -nokeys  > client.cer
#按造步驟產生key之後，使用kafka-connect連elasticsearch時，需先將elastic-certificates.p12匯入系統根憑證儲存的地方。
#keytool -importkeystore -deststorepass changeit -destkeystore /etc/pki/ca-trust/extracted/java/cacerts -srckeystore elastic/config/elastic-certificates.p12 -srcstoretype pkcs12
#curl -XPOST "http://172.168.113.110:8083/connectors" -H 'Content-Type: application/json' -d'
# {
#  "name": "connect-channel",
#  "config": {
#   "topics": "connect-channell",
#   "connector.class": "io.confluent.connect.elasticsearch.ElasticsearchSinkConnector",
#   "connection.username": "elastic",
#   "connection.password": "Admin@@@111",
#   "connection.url": "https://172.168.113.110:9200",
#   "tasks.max": "1"
# }
#}'