#!/bin/bash

defaul_rpm_dir=rpm/docker_dir
docker_pre_dir=docker_pre
docker_dir=docker

#Redhat一定要刪除舊的檔案(避免衝突)
delete_docker(){
sudo yum remove docker docker-client docker-client-latest docker-common docker-latest docker-latest-logrotate docker-logrotate docker-engine podman runc
}

function valid_file(){
file_num=`find $1 -type f -name *.rpm | wc -l`
if [ ${file_num} != 0 ];then
echo "${file_num}個檔案存在"
return 1
else
echo "檔案不存在"
return 0
fi
}

install_docker(){
#安裝已完成下載的檔案
#解壓縮 
valid_file "$defaul_rpm_dir/$docker_dir/"
swag=$?

if [ "${swag}" == 1 ]; then
	echo "資料夾存在"
	#安裝資料夾中的rpm檔案
	rpm -Uivh $defaul_rpm_dir/$docker_pre_dir/*.rpm
	rpm -Uivh $defaul_rpm_dir/$docker_dir/*.rpm
else
	echo "資料夾不存在"
fi

}

start_docker(){
#啟動docker
#安裝後第一次啟動docker
systemctl start docker.service
systemctl enable docker.service
}

install_docker
start_docker
