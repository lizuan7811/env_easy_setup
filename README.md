![charsphoto](https://user-images.githubusercontent.com/85433317/221773032-08a2a206-feb0-440a-a377-fe7d8e494b7a.png)

# env_easy_setup
### Use Kafka、Kibana、Elasticsearch、RKE2 opts...!

### RKE2(k8s)
1. 使用Deploymnent佈署Pod，若Clusters中的一Node關閉，過幾分鐘後，Master會自動偵測Node及Pod狀態，更新Pod的狀態(Running->Terminatin)，重新佈署新的Pod到活著的Node，直到關閉或斷線的Node再次連線到Cluster，就會刪掉Deployment佈署的被標記為Terminating的Pod，而Statefulset原本被Terminating的Pod，連線後，會再次活起來。
2. Kafka connector 有時會因連線超時，中斷資料傳輸，需要重新啟動。
