#!/bin/bash
#Redhat一定要刪除舊的檔案(避免衝突)
sudo yum remove docker docker-client docker-client-latest docker-common docker-latest docker-latest-logrotate docker-logrotate docker-engine podman runc

#安裝已完成下載的檔案
#解壓縮 
tar zxvf *.tar.gz

#依下表中檔案順序安裝Docker
rpm -Uivh *.rpm
#安裝後第一次啟動docker
systemctl start docker.service

systemctl start docker.service
systemctl enable docker.service

#將harbor檔案解壓縮到/opt/harbor
tar zxvf harbor.tar.gz -C /opt