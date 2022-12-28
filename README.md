# env_easy_setup


### Use Kafka、Kibana、Elasticsearch、RKE2 opts...!

### RKE2(k8s)
1. 使用Deploymnent佈署pod，若Clusters中的一Node關閉，過幾分鐘後，master會自動偵測node及pod狀態，調整pod的狀態以及刪除pod，重新佈署新的pod到活著的node，直到關閉或斷線的node再次連線到cluster，就會刪掉deployment佈署的被標記為terminating的pod，而statefulset原本被terminating的pod，連線後，會再次活起來。
