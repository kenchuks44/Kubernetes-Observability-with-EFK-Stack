## Kubernetes Observability with EFK Stack

![Screenshot (754)](https://github.com/kenchuks44/Kubernetes-Observability-with-EFK-Stack/assets/88329191/54d3b174-698c-4a18-95ab-1f0559c8cc59)

Logging is crucial in application development. We regularly add log lines to our code for future reference, particularly when troubleshooting problems. With smaller applications, this can be easily managed by checking logs with kubectl logs command. However, as applications grow, particularly in a microservices design with several instances, finding and managing logs becomes difficult. Running kubectl logs on many pods for different services is impractical. To address this issue, we employ an effective log management system that can quickly retrieve the information we require when problems are encountered.

## What is EFK?
EFK stands for Elasticsearch, Fluentd, and Kibana:

- Elasticsearch: NoSQL database based on the Lucene search engine. A real-time distributed search and analytics engine. It’s where our logs are stored and can be queried.
- Fluentd: An open-source superfast, lightweight and highly scalable data collector, which unifies data collection and consumption for better use and understanding by humans and machines. In our context, it’s responsible for collecting logs from Kubernetes nodes and forwarding them to Elasticsearch.
- Kibana: A visualization layer that works on top of Elasticsearch, providing a UI to visualize and query the data.

Traditional logging solutions, like centralized logging servers or logging agents that write to a file on disk, were designed for static infrastructure. They assume that servers are long-lived and that logs can be written to disk or sent to a centralized server without much transformation.

However, in a Kubernetes environment:

- Containers can be killed and started dynamically, which means logs can be lost if not handled correctly.
- With potentially thousands of containers running, the volume of logs can be overwhelming.
- Different microservices might log in different formats, requiring normalization.
  
The EFK stack, being cloud-native, addresses these challenges by providing a scalable, flexible, and unified logging solution that’s designed for the dynamic nature of containerized applications.

## Requirements
- Kubernetes cluster running
- Helm installed
- Kubectl installed

## Setting Up the EFK Stack

## Step 1: Deploying Elasticsearch
To deploy Elasticsearch, we first create a dedicated namespace called efk to keep our Elasticsearch and other logging components organized within the Kubernetes cluster.
```
kubectl create namespace efk
```
Next, we add the Elastic Helm chart repository with the command below:
```
helm repo add elastic https://helm.elastic.co
```
Then, we install Elasticsearch using Helm:
```
helm install elasticsearch elastic/elasticsearch \
  --set replicas=1 \
  --set resources.requests.memory="512Mi" \
  --set resources.requests.cpu="500m" \
  --set persistence.enabled=false \
  --set service.type=LoadBalance -n efk
```

This Helm installation command deploys Elasticsearch within the efk namespace. It also configures Elasticsearch to use a LoadBalancer service type.
After the installation, we retrieve the username and password for Elasticsearch using the following commands:

To get the username:
```
kubectl get secrets --namespace=efk elasticsearch-master-credentials -ojsonpath='{.data.username}' | base64 -d
```

To get the password:
```
kubectl get secrets --namespace=efk elasticsearch-master-credentials -ojsonpath='{.data.password}' | base64 -d
```

These commands fetch the credentials required to access Elasticsearch securely. The username and password are stored in a Kubernetes secret called elasticsearch-master-credentials within the efk namespace. The base64 -d part is used to decode the base64-encoded values for human-readable access.

![image](https://github.com/kenchuks44/Kubernetes-Observability-with-EFK-Stack/assets/88329191/004c01f0-0085-45cd-9f06-daf209cf45c4)

Next, we obtain the LoadBalancer IP for the service to enable us access Elasticsearch through the browser
```
kubectl get svc -n efk
```

![image1](https://github.com/kenchuks44/Kubernetes-Observability-with-EFK-Stack/assets/88329191/a6b49f03-975b-4dc0-ae3a-036f42b4fd85)

With the LoadBalancer IP, we then test Elasticsearch in a browser. Elasticsearch typically runs on port 9200.
Note that when Elasticsearch is configured to use TLS and requires credentials for authentication, you will need to use HTTPS and provide the credentials in the URL.
When you access this URL, your browser should prompt you for the username and password. Enter the credentials you obtained earlier, and you should be able to access Elasticsearch securely over HTTPS.

![image3](https://github.com/kenchuks44/Kubernetes-Observability-with-EFK-Stack/assets/88329191/c3a2e49c-a7ef-4ebc-8866-ceed8f9c04da)

We should get a JSON output specifying some cluster details as below
```
{
 "name" : "<pod_name_that_received_the_request>",
 "cluster_name" : "elasticsearch",
 "cluster_uuid" : "<some_id>",
 "version" : {
 "number" : "<es_version_deployed>",
 "build_flavor" : "default",
 "build_type" : "docker",
 "build_hash" : "<some_hash>",
 "build_date" : "<some_date>",
 "build_snapshot" : false,
 …
 …
 …
 },
 "tagline" : "You Know, for Search"
}
```

![image4](https://github.com/kenchuks44/Kubernetes-Observability-with-EFK-Stack/assets/88329191/41aa1bc1-f735-4815-bb26-b5f0bb325027)

## Step 2: Deploying Kibana
Kibana provides a web UI to visualize logs stored in Elasticsearch. To set up Kibana and make it accessible through a LoadBalancer service type, we use the following Helm installation command:
```
helm install kibana-new elastic/kibana \
  --set replicas=1 \
  --set resources.requests.memory="500Mi" \
  --set resources.requests.cpu="500m" \
  --set service.type=LoadBalancer -n efk
```

We next obtain the LoadBalancer IP for the service and open the Kibana UI using the following commands:

To get the LoadBalancer IP:
```
kubectl get svc -n efk
```
![image6](https://github.com/kenchuks44/Kubernetes-Observability-with-EFK-Stack/assets/88329191/50711c17-0582-4012-8475-85216e797538)

After obtaining the LoadBalancer IP, we open Kibana in a browser. Kibana typically runs on port 5601
Note: We use the username and password obtained for Elasticsearch above.

![image7](https://github.com/kenchuks44/Kubernetes-Observability-with-EFK-Stack/assets/88329191/fcd445be-e352-47fe-925c-566719878081)

![image8](https://github.com/kenchuks44/Kubernetes-Observability-with-EFK-Stack/assets/88329191/a444532d-736d-41e7-b52d-9b464f453748)

![image9](https://github.com/kenchuks44/Kubernetes-Observability-with-EFK-Stack/assets/88329191/6b67a298-c7d8-44f8-ae81-c3b94af34edf)

## Step 3: Installing Fluent Bit
Firstly, we add the Fluent Bit Helm Repository:
```
helm repo add fluent https://fluent.github.io/helm-charts
```

Next, we configure fluentbit. Before installing the Helm chart for Fluent Bit, it’s essential to configure the Fluent Bit to correctly access Elasticsearch, which may be part of your EFK (Elasticsearch, Fluent Bit, Kibana) stack. To do this, we need to set up a configuration file. Here, we obtain the values file for Fluent Bit and save it in YAML format:
```
helm show values fluent/fluent-bit > fluentbit-values.yaml
```

Next, we make changes to this file to suit our specific Elasticsearch setup and logging requirements. Once configured, we then proceed to install Fluent Bit using Helm with our custom settings.
```
.........
.........
config:
  service: |
    [SERVICE]
        Daemon Off
        Flush {{ .Values.flush }}
        Log_Level {{ .Values.logLevel }}
        Parsers_File /fluent-bit/etc/parsers.conf
        Parsers_File /fluent-bit/etc/conf/custom_parsers.conf
        HTTP_Server On
        HTTP_Listen 0.0.0.0
        HTTP_Port {{ .Values.metricsPort }}
        Health_Check On

  ## https://docs.fluentbit.io/manual/pipeline/inputs
  inputs: |
    [INPUT]
        Name tail
        Path /var/log/containers/*.log
        multiline.parser docker, cri
        Tag kube.*
        Mem_Buf_Limit 5MB
        Skip_Long_Lines On

    [INPUT]
        Name systemd
        Tag host.*
        Systemd_Filter _SYSTEMD_UNIT=kubelet.service
        Read_From_Tail On

  ## https://docs.fluentbit.io/manual/pipeline/filters
  filters: |
    [FILTER]
        Name kubernetes
        Match kube.*
        Merge_Log On
        Keep_Log Off
        K8S-Logging.Parser On
        K8S-Logging.Exclude On


  ## https://docs.fluentbit.io/manual/pipeline/outputs
  outputs: |
    [OUTPUT]
        Name es
        Match kube.*
        Index fluent-bit
        Type  _doc
        Host elasticsearch-master
        Port 9200
        HTTP_User elastic
        HTTP_Passwd <elasticsearch-password>
        tls On
        tls.verify Off
        Logstash_Format On
        Logstash_Prefix logstash
        Retry_Limit False
        Suppress_Type_Name On

    [OUTPUT]
        Name es
        Match host.*
        Index fluent-bit
        Type  _doc
        Host elasticsearch-master
        Port 9200
        HTTP_User elastic
        HTTP_Passwd <elasticsearch-password>
        tls On
        tls.verify Off
        Logstash_Format On
        Logstash_Prefix node
        Retry_Limit False
        Suppress_Type_Name On

......
......
```

The provided configuration defines how Fluent Bit, a log processor, should operate.

In the `config` section, we specify settings for its services, such as the log flush frequency and log levels.

The `inputs` section outlines the sources of log data, including container logs and system logs.

The line below in the config is responsible for reading all the container logs:
```
Path /var/log/containers/*.log
```


The `filters` section, `kubernetes` filter processes logs that match the "kube.*" tag, enabling log merging and parser usage while excluding keeping original logs.

`Name kubernetes`: This sets the filter name to "kubernetes." Filters are plugins that manipulate log records. Here, the "kubernetes" filter processes logs related to Kubernetes containers.

`Match kube.*`: This line specifies that the filter should be applied to logs with tags matching "kube.*." Tags are labels assigned to log entries to categorize them. In this context, logs generated by Kubernetes containers will have tags that start with "kube."

`Merge_Log On`: This configuration option enables log merging. It means that Fluent Bit will merge multiline log entries into a single log record when necessary. This is useful for log entries that span multiple lines.
  
`Keep_Log Off`: By setting this to "Off," Fluent Bit discards the original log message after it's merged. This is typically done to prevent duplicate log entries when merging multiline logs.

`K8S-Logging.Parser On`: This line turns on the Kubernetes-logging parser. Kubernetes logs often have specific formatting, and this parser helps Fluent Bit understand and parse those logs correctly.

`K8S-Logging.Exclude On`: This configuration option excludes the original log message after parsing it with the Kubernetes-logging parser. It ensures that only the parsed, structured log data is retained.


`Output Configuration`:

- Fluent Bit sends logs to Elasticsearch:
- The first output block sends logs matching “kube.*” tags to Elasticsearch at “elasticsearch-master” on port 9200. It provides authentication using an “elastic” username and password with TLS enabled.
- The second output block sends logs matching “host.*” tags to Elasticsearch in a similar manner, but prefixes them with “node” in the Logstash index.

Observing closely, we see that logs from all applications are going in the same ES index (We have specified Index fluent-bit, it goes into a single index by default)

At first glance, having only one index does not appear to be a problem. However, if numerous applications start using their own log formats, a collision is certain to occur sooner or later.

`Logs will go to ES as JSON docs, and ES maintains a mapping for each index. So, if you are using a single index, then if any new document comes with a field with the same name, but if the type is different than what is already saved in the index field mapping, then those log events will get dropped.`

However, we do not intend to input separate input-output config pairs for all applications. Hence, we will utilize a Lua script and a simple Lua filter for adding the index field in the log event itself and then use that field in the output plugin in the Logstash_Prefix_Key

```
.........
.........
luaScripts:
  setIndex.lua: |
    function set_index(tag, timestamp, record)
        index = "kenchuks-"
        if record["kubernetes"] ~= nil then
            if record["kubernetes"]["namespace_name"] ~= nil then
                if record["kubernetes"]["container_name"] ~= nil then
                    record["es_index"] = index
                        .. record["kubernetes"]["namespace_name"]
                        .. "-"
                        .. record["kubernetes"]["container_name"]
                    return 1, timestamp, record
                end
                record["es_index"] = index
                    .. record["kubernetes"]["namespace_name"]
                return 1, timestamp, record
            end
        end
        return 1, timestamp, record
    end
## https://docs.fluentbit.io/manual/administration/configuring-fluent-bit/classic-mode/configuration-file
config:
  service: |
    [SERVICE]
        Daemon Off
        Flush {{ .Values.flush }}
        Log_Level {{ .Values.logLevel }}
        Parsers_File /fluent-bit/etc/parsers.conf
        Parsers_File /fluent-bit/etc/conf/custom_parsers.conf
        HTTP_Server On
        HTTP_Listen 0.0.0.0
        HTTP_Port {{ .Values.metricsPort }}
        Health_Check On

  ## https://docs.fluentbit.io/manual/pipeline/inputs
  inputs: |
    [INPUT]
        Name tail
        Path /var/log/containers/*.log
        multiline.parser docker, cri
        Tag kube.*
        Mem_Buf_Limit 5MB
        Skip_Long_Lines On

    [INPUT]
        Name systemd
        Tag host.*
        Systemd_Filter _SYSTEMD_UNIT=kubelet.service
        Read_From_Tail On

  ## https://docs.fluentbit.io/manual/pipeline/filters
  filters: |
    [FILTER]
        Name kubernetes
        Match kube.*
        Merge_Log On
        Keep_Log Off
        K8S-Logging.Parser On
        K8S-Logging.Exclude On

    [FILTER]
        Name lua
        Match kube.*
        script /fluent-bit/scripts/setIndex.lua
        call set_index

  ## https://docs.fluentbit.io/manual/pipeline/outputs
  outputs: |
    [OUTPUT]
        Name es
        Match kube.*
        Type  _doc
        Host elasticsearch-master
        Port 9200
        HTTP_User elastic
        HTTP_Passwd <elasticsearch-password>
        tls On
        tls.verify Off
        Logstash_Format On
        Logstash_Prefix logstash
        Retry_Limit False
        Suppress_Type_Name On

    [OUTPUT]
        Name es
        Match host.*
        Type  _doc
        Host elasticsearch-master
        Port 9200
        HTTP_User elastic
        HTTP_Passwd <elasticsearch-password>
        tls On
        tls.verify Off
        Logstash_Format On
        Logstash_Prefix node
        Retry_Limit False
        Suppress_Type_Name On

......
......
```

After updating the above configuration, we then install the helm chart with the custom-value file (`fluentbit-values.yaml`)
```
helm install fluent-bit fluent/fluent-bit -f fluentbit-values.yaml -n efk \
 --set elasticsearch.host=elasticsearch-master \
  --set resources.requests.memory="200Mi" \
  --set resources.requests.cpu="100m" \
  --set replicas=1
```

![image11](https://github.com/kenchuks44/Kubernetes-Observability-with-EFK-Stack/assets/88329191/08249ef4-cdbd-4611-9c5a-b9b1caf429cd)

![image13](https://github.com/kenchuks44/Kubernetes-Observability-with-EFK-Stack/assets/88329191/5c98be3d-b1b9-44f0-8f32-b2d08f0cf07b)

KIndly note that for the above configuration, in the INPUT plugin, Fluent Bit is sending all container logs as seen below
```
...
...
config:
  service: |
  ...
  ...
  inputs: |
    [INPUT]
        Name tail
        Path /var/log/containers/*.log
        multiline.parser docker, cri
        Tag kube.*
        Mem_Buf_Limit 5MB
        Skip_Long_Lines On
...
...
```

```
[INPUT]
        Name tail
        Path /var/log/containers/*.log
        multiline.parser docker, cri
        Tag kube.*
        Mem_Buf_Limit 5MB
        Skip_Long_Lines On
...
...
```

However, in order to have fine-grained control over which logs Fluenbit should listen to, we can have separate INPUT plugins for each application, and specify an Alias for each of the INPUT. This way we will be able to monitor the log volume for each of the apps separately — this Alias directly gets added to the metrics that Fluentbit emits.

```
...
...
  inputs: |
    [INPUT]
        Name tail
        Alias fluentbit
        Path /var/log/containers/fluentbit*.log
        multiline.parser docker, cri
        Tag kube.*
        Mem_Buf_Limit 5MB
        Skip_Long_Lines On
    [INPUT]
        Name tail
        Alias chuks
        Path /var/log/containers/chuks*.log
        multiline.parser docker, cri
        Tag kube.*
        Mem_Buf_Limit 5MB
        Skip_Long_Lines On
    [INPUT]
        Name tail
        Alias cart
        Path /var/log/containers/cart*.log
        multiline.parser docker, cri
        Tag kube.*
        Mem_Buf_Limit 5MB
        Skip_Long_Lines On
...
...
```

Note that the choice of log file path depends on where an application writes its logs. If a log file path has not been specified in the application, the default destination for the logs is typically the STDOUT, which represents the standard output stream. This is a common practice in containerized applications, where logs are directed to STDOUT, making them accessible and manageable through container orchestration platforms like Kubernetes.


## Log Visualization
By default, Fluentbit will start gathering container logs from all the pods that are present in the cluster and will push these to the newly deployed ES cluster.

It also listens to the systemd metrics and pushes them to the same ES cluster.

For exploring the logs, first, we verify the newly created indices are showing on Kibana.

Go to Kibana → Stack Management → Index Management, and under the Indices tab, we should see the 2 newly created indices with the names logstash-yyyy.MM.dd and node-yyyy.MM.dd

![image14](https://github.com/kenchuks44/Kubernetes-Observability-with-EFK-Stack/assets/88329191/ff24b8c0-6b93-486c-b9e3-4675c2dffbfc)

![image15](https://github.com/kenchuks44/Kubernetes-Observability-with-EFK-Stack/assets/88329191/a8f2a9bd-e105-49b1-ac8c-fb39e25a686d)

For checking application logs on Kibana, we need to create an Index Pattern for the app (one-time activity).

Index patterns can be created by: Go to Kibana → Stack Management → Data Views → Create data view→ Specify your index pattern and select a timestamp field → save data view to Kibana

![image16](https://github.com/kenchuks44/Kubernetes-Observability-with-EFK-Stack/assets/88329191/da076c09-1fc1-4070-a60b-a6b4ad34e7b0)

![image17](https://github.com/kenchuks44/Kubernetes-Observability-with-EFK-Stack/assets/88329191/05ab8bee-4d6a-49a4-818c-ea44cac77659)

Next, you can now check your logs by going to Discover → Select your newly created index pattern from the dropdown → Search Logs

![image18](https://github.com/kenchuks44/Kubernetes-Observability-with-EFK-Stack/assets/88329191/25cf85c7-85f9-4759-b2c6-c84977d136e5)

To test Fluent Bit by sending logs to Elasticsearch and visualize them in Kibana, we will start a pod that creates logs continuously using test-pod yaml file below. We will then try to see these logs inside Kibana
```
apiVersion: v1
kind: Pod
metadata:
  name: counter
spec:
  containers:
  - name: count
    image: busybox
    args: [/bin/sh, -c,'i=0; while true; do echo "EFK is a robust logging solution! $i"; i=$((i+1)); sleep 1; done']
```

Apply the manifest

```
kubectl create -f test-pod.yaml
```

We then proceed to Kibana to view the logs from this pod as being picked up by fluentd and stored at Elasticsearch



















