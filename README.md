# env_easy_setup


### Use Kafka、Kibana、Elasticsearch、RKE2 opts...!

### RKE2(k8s)
1. 使用Deploymnent或是statefulset佈署pod，若Clusters中的一Node關閉，過幾分鐘後，master會自動偵測node及pod狀態，調整pod的狀態以及刪除pod，重新佈署。
