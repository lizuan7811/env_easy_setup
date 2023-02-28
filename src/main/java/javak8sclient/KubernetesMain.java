package javak8sclient;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Objects;

import com.google.gson.reflect.TypeToken;

import io.kubernetes.client.ProtoClient;
import io.kubernetes.client.ProtoClient.ObjectOrStatus;
import io.kubernetes.client.custom.IntOrString;
import io.kubernetes.client.custom.V1Patch;
import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.openapi.ApiException;
import io.kubernetes.client.openapi.Configuration;
import io.kubernetes.client.openapi.apis.AppsV1Api;
import io.kubernetes.client.openapi.apis.CoreV1Api;
import io.kubernetes.client.openapi.models.V1Container;
import io.kubernetes.client.openapi.models.V1DeleteOptions;
import io.kubernetes.client.openapi.models.V1Deployment;
import io.kubernetes.client.openapi.models.V1Namespace;
import io.kubernetes.client.openapi.models.V1ObjectMeta;
import io.kubernetes.client.openapi.models.V1Pod;
import io.kubernetes.client.openapi.models.V1PodBuilder;
import io.kubernetes.client.openapi.models.V1PodList;
import io.kubernetes.client.openapi.models.V1PodSpec;
import io.kubernetes.client.openapi.models.V1Service;
import io.kubernetes.client.openapi.models.V1ServiceBuilder;
import io.kubernetes.client.proto.Meta.ObjectMeta;
import io.kubernetes.client.proto.V1.Namespace;
import io.kubernetes.client.proto.V1.NamespaceSpec;
import io.kubernetes.client.proto.V1.PodList;
import io.kubernetes.client.util.ClientBuilder;
import io.kubernetes.client.util.KubeConfig;
import io.kubernetes.client.util.PatchUtils;
import io.kubernetes.client.util.Watch;
import io.kubernetes.client.util.Yaml;
import io.spring.gradle.dependencymanagement.org.codehaus.plexus.util.FileUtils;

public class KubernetesMain {

	private final static String CONFIG_FILE = "C:\\Users\\ASUS\\eclipse-workspace\\env_easy_setup\\src\\main\\resources\\config";

	static String jsonPatchStr = "[{\"op\":\"replace\",\"path\":\"/spec/template/spec/terminationGracePeriodSeconds\",\"value\":27}]";
	static String strategicMergePatchStr = "{\"metadata\":{\"$deleteFromPrimitiveList/finalizers\":[\"example.com/test\"]}}";
	static String jsonDeploymentStr = "{\"kind\":\"Deployment\",\"apiVersion\":\"apps/v1\",\"metadata\":{\"name\":\"hello-node1\",\"finalizers\":[\"example.com/test\"],\"labels\":{\"run\":\"hello-node1\"}},\"spec\":{\"replicas\":1,\"selector\":{\"matchLabels\":{\"run\":\"hello-node1\"}},\"template\":{\"metadata\":{\"creationTimestamp\":null,\"labels\":{\"run\":\"hello-node1\"}},\"spec\":{\"terminationGracePeriodSeconds\":30,\"containers\":[{\"name\":\"hello-node1\",\"image\":\"hello-node:v1\",\"ports\":[{\"containerPort\":8080,\"protocol\":\"TCP\"}],\"resources\":{}}]}},\"strategy\":{}},\"status\":{}}";
	static String applyYamlStr = "{\"kind\":\"Deployment\",\"apiVersion\":\"apps/v1\",\"metadata\":{\"name\":\"hello-node1\",\"finalizers\":[\"example.com/test\"],\"labels\":{\"run\":\"hello-node1\"}},\"spec\":{\"replicas\":1,\"selector\":{\"matchLabels\":{\"run\":\"hello-node1\"}},\"template\":{\"metadata\":{\"creationTimestamp\":null,\"labels\":{\"run\":\"hello-node1\"}},\"spec\":{\"terminationGracePeriodSeconds\":30,\"containers\":[{\"name\":\"hello-node1\",\"image\":\"hello-node:v2\",\"ports\":[{\"containerPort\":8080,\"protocol\":\"TCP\"}],\"resources\":{}}]}},\"strategy\":{}},\"status\":{}}";

	public static void main(String[] args) {
		
		yamlExample();
//		fluentExample();
//		patchExample();
//		protoBaseExample();
	}

	@SuppressWarnings("deprecation")
	private static void yamlExample() {
		V1Pod pod=new V1PodBuilder().withNewMetadata().withName("apod").endMetadata().withNewSpec().addNewContainer().withName("www").withImage("nginx").withNewResources().withLimits(new HashMap<>()).endResources().endContainer().endSpec().build();
		System.out.println(Yaml.dump(pod));
		
		V1Service v1Svc=new V1ServiceBuilder().withNewMetadata().withName("aservice").endMetadata().withNewSpec().withSessionAffinity("ClientIP").withType("NodePort").addNewPort().withProtocol("TCP").withName("client").withPort(8080).withNodePort(8080).withTargetPort(new IntOrString(8080)).endPort().endSpec().build();
		System.out.println(Yaml.dump(v1Svc));
		
		try {
			ApiClient client=ClientBuilder.kubeconfig(KubeConfig.loadKubeConfig(Files.newBufferedReader(Paths.get(CONFIG_FILE)))).build();
			Configuration.setDefaultApiClient(client);
			Yaml.addModelMap("v1","Service",V1Service.class);
			File file=new File("test-svc.yaml");
			V1Service yamlSvc=(V1Service)Yaml.load(file);
			CoreV1Api api=new CoreV1Api();
			V1Service createResult=api.createNamespacedService("default",yamlSvc,null,null,null,null);
			System.out.println(createResult);
			
			V1Service deleteResult=api.deleteNamespacedService(yamlSvc.getMetadata().getName(),"default",null,null,null,null,null,new V1DeleteOptions());
			System.out.println(deleteResult);
			
			
		} catch (IOException | ApiException e) {
			e.printStackTrace();
		}

		
		
		
		
	}
	
	
	
	private static void fluentExample() {
		try {
			ApiClient client=ClientBuilder.kubeconfig(KubeConfig.loadKubeConfig(Files.newBufferedReader(Paths.get(CONFIG_FILE)))).build();

			Configuration.setDefaultApiClient(client);
			
			CoreV1Api api=new CoreV1Api();
			
			V1Pod pod=new V1PodBuilder().withNewMetadata().withName("apod").endMetadata().withNewSpec().addNewContainer().withName("www").withImage("nginx").endContainer().endSpec().build();
			
			api.createNamespacedPod("default",pod,null,null,null,null);
		
			V1Pod pod2= new V1Pod().metadata(new V1ObjectMeta().name("anotherpod")).spec(new V1PodSpec().containers(Arrays.asList(new V1Container().name("www").image("nginx"))));
		
			api.createNamespacedPod("default",pod2,null,null,null,null);
			
			V1PodList list=api.listNamespacedPod("default",null,null,null,null,null,null,null, null,null,null);
			list.getItems().stream().forEach(item->System.out.println(item.getMetadata().getName()));
			
		} catch (IOException | ApiException e) {
			e.printStackTrace();
		}

		
	}
	
	
	private static void patchExample() {
		try (BufferedWriter bw = Files.newBufferedWriter(Paths.get(
				"C:\\Users\\ASUS\\eclipse-workspace\\env_easy_setup\\src\\main\\resources\\printPatchDeployment.txt"),
				StandardOpenOption.CREATE_NEW)) {
//		try {
			AppsV1Api api = new AppsV1Api(ClientBuilder
					.kubeconfig(KubeConfig.loadKubeConfig(Files.newBufferedReader((Paths.get(CONFIG_FILE))))).build());

			V1Deployment body = Configuration.getDefaultApiClient().getJSON().deserialize(jsonDeploymentStr,
					V1Deployment.class);
			V1Deployment deploy1 = api.createNamespacedDeployment("default", body, null, null, null, null);

			bw.write("original deployment" + deploy1);
			bw.newLine();
			V1Deployment deploy2 = PatchUtils.patch(
					V1Deployment.class, () -> api.patchNamespacedDeploymentCall("hello-node1", "default",
							new V1Patch(jsonPatchStr), null, null, null, null, null, null),
					V1Patch.PATCH_FORMAT_JSON_PATCH, api.getApiClient());

			bw.write("json-patched deployment" + deploy2);
			bw.newLine();
			V1Deployment deploy3 = PatchUtils.patch(V1Deployment.class,
					() -> api.patchNamespacedDeploymentCall("hello-node1", "default",
							new V1Patch(strategicMergePatchStr), null, null, null, null, null, null),
					V1Patch.PATCH_FORMAT_STRATEGIC_MERGE_PATCH, api.getApiClient());
			bw.write("strategic-merge-patched deployment" + deploy3);
			bw.newLine();
			V1Deployment deploy4 = PatchUtils.patch(V1Deployment.class,
					() -> api.patchNamespacedDeploymentCall("hello-node1", "default", new V1Patch(applyYamlStr), null,
							null, "example-field-manager", null, true, null),
					V1Patch.PATCH_FORMAT_APPLY_YAML, api.getApiClient());
			bw.write("application/apply-patch+yaml deployment " + deploy4);

			bw.flush();
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	private static void protoBaseExample() {
//		try(BufferedWriter bw=Files.newBufferedWriter(Paths.get("C:\\Users\\ASUS\\eclipse-workspace\\env_easy_setup\\src\\main\\resources\\printProtoPod.txt"),StandardOpenOption.CREATE_NEW)) {
		try {
			ApiClient apiClient = ClientBuilder
					.kubeconfig(KubeConfig.loadKubeConfig(Files.newBufferedReader(Paths.get(CONFIG_FILE)))).build();
			Configuration.setDefaultApiClient(apiClient);

			ProtoClient protoClient = new ProtoClient(apiClient);
			ObjectOrStatus<PodList> list = protoClient.list(PodList.newBuilder(), "/api/v1/namespaces/default/pods");

//			list.object.getItemsList().stream().forEach(item->{try {
//				bw.write(item.toString());
//				bw.newLine();
//				bw.flush();
//				
//			} catch (IOException e) {
//				e.printStackTrace();
//			}});

			Namespace namespace = Namespace.newBuilder()
					.setMetadata(ObjectMeta.newBuilder().setName("trynamespace").build()).build();
			ObjectOrStatus<Namespace> ns = protoClient.create(namespace, "/api/v1/namespaces", "v1", "Namespace");
			System.out.println(ns);

			if (Objects.nonNull(ns.object)) {
//			namespace=ns.object.toBuilder().setSpec(NamespaceSpec.newBuilder().addFinalizers("test").build()).build();

				namespace = ns.object.toBuilder().setSpec(NamespaceSpec.newBuilder().build()).build();
				ns = protoClient.update(namespace, "/api/v1/namespaces/trynamespace", "v1", "Namespace");
				System.out.println(ns.status);
			}

			ns = protoClient.delete(Namespace.newBuilder(), "/api/v1/namespaces/trynamespace");
			System.out.println(ns);

		} catch (IOException | ApiException e) {
			e.printStackTrace();
		}
	}

	private static void printPodBaseExample() {
		try (BufferedWriter bw = Files.newBufferedWriter(
				Paths.get("C:\\Users\\ASUS\\eclipse-workspace\\env_easy_setup\\src\\main\\resources\\printPod.txt"),
				StandardOpenOption.CREATE_NEW)) {

			ApiClient client = ClientBuilder
					.kubeconfig(KubeConfig.loadKubeConfig(Files.newBufferedReader(Paths.get(CONFIG_FILE)))).build();
//			client = Config.fromConfig("C:\\Users\\ASUS\\eclipse-workspace\\env_easy_setup\\src\\main\\resources\\config");
			Configuration.setDefaultApiClient(client);

			CoreV1Api api = new CoreV1Api();

			Watch<V1Namespace> watch = Watch.createWatch(client,
					api.listNamespaceCall(null, null, null, null, null, null, null, null, null, null, null),
					new TypeToken<Watch.Response<V1Namespace>>() {
					}.getType());

//			watch.forEach(names->{
//				try {
//				bw.write(names.toString());
//				bw.newLine();
//					bw.flush();
//				} catch (IOException e) {
//					e.printStackTrace();
//				}
//			});

			V1PodList list = api.listPodForAllNamespaces(null, null, null, null, null, null, null, null, null, null);
			list.getItems().stream().forEach(item -> {
				try {
					bw.write(item.toString());
					bw.newLine();
					bw.flush();

				} catch (IOException e) {
					e.printStackTrace();
				}
			});

		} catch (ApiException | IOException e) {
			e.printStackTrace();
		}
	}

}
