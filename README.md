## Kubernetes Observability with EFK Stack

Logging is crucial in application development. We frequently add log lines to our code for future reference, particularly when troubleshooting problems. In smaller applications with less traffic, checking logs is simple. To access an individual pod's logs, we simply use the kubectl logs command.
However, as applications develop, particularly in a microservices design with several instances, finding and managing logs becomes difficult. Running kubectl logs on many pods for different services is impractical. To address this issue, we need an effective log management system that can quickly retrieve the information we require when problems are encountered.

## What is EFK?
EFK stands for Elasticsearch, Fluentd, and Kibana:

- Elasticsearch: A real-time distributed search and analytics engine. It’s where your logs are stored and can be queried.
- Fluentd: An open-source data collector, which unifies data collection and consumption for better use and understanding by humans and machines. In our context, it’s responsible for collecting logs from Kubernetes nodes and forwarding them to Elasticsearch.
- Kibana: A visualization layer that works on top of Elasticsearch, providing a UI to visualize and query the data.
