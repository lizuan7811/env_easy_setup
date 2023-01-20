#!/bin/bash

#將harbor檔案解壓縮到/opt/harbor
defaul_rpm_dir=rpm
harbor_dir=harbor

default_harbor_dir=/opt/$harbor_dir

tar zxvf $defaul_rpm_dir/$harbor_dir/harbor.tar.gz -C /opt

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

#讀取image檔案並完成tag以及push 上harbor。



#修改yml檔案內容



#確認harbor已經完成解壓縮，複製config檔案並修改相對應的參數。
function install_harbor(){

valid_file "/opt/harbor"

exist_tag=$?

if [ "${exist_tag}" eq 1 ];then

cp $default_harbor_dir/harbor.yml.tmpl $default_harbor_dir/harbor.yml


fi


}
