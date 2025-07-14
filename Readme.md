# Cast AI All-In-One (AIO) Helm Chart
This helm chart acts are a single resource to get rid of handling X different helm charts and run shell scripts to onboard CAST AI. 

## Supported components
* castai-agent
* castai-cluster-controller
* castai-evictor
* castai-pod-mutator
* castai-spot-handler
* castai-workload-autoscaler

## Supported provider
- [x] Anywhere
- [ ] AKS
- [x] EKS
- [ ] GKE

## How to deploy
```
git clone https://github.com/kisahm/castai-aio.git
cd castai-aio
helm dependency build ./chart
helm upgrade -i castai-aio ./chart --create-namespace -n castai-agent -f myvalue.yaml
```

### Example EKS (active mode)
custom values file: 
```
---
global:
  apiKey: "YOUR_CASTAI_API_KEY"
  eks:
    credentials:
      accessKeyId: "YOUR_AWS_ACCESS_KEY_ID"
      secretAccessKey: "YOUR_AWS_SECRET_ACCESS_KEY"
      sessionToken: "" # optional

castai-agent: 
  apiKey: "YOUR_CASTAI_API_KEY"
  provider: eks

castai-spot-handler:
  castai:
    provider: "eks"

infrastructureAutoscaling:
  enabled: true
```

outcome:
```
% kubectl get po -n castai-agent 
NAME                                                     READY   STATUS      RESTARTS      AGE
castai-agent-b69dc6dd-5bs8z                              2/2     Running     0             11m
castai-agent-b69dc6dd-tftj9                              2/2     Running     0             12m
castai-agent-cpvpa-964fc94b6-zqxd2                       1/1     Running     0             12m
castai-aio-castai-workload-autoscaler-6cc559cf5f-mzr74   1/1     Running     0             12m
castai-aio-castai-workload-autoscaler-6cc559cf5f-wdgrr   1/1     Running     1 (11m ago)   12m
castai-cluster-controller-58686bdfbc-4wt4g               2/2     Running     0             12m
castai-cluster-controller-58686bdfbc-ckn4n               2/2     Running     0             12m
castai-pod-mutator-6476fdc549-hvptm                      1/1     Running     0             12m
castai-pod-mutator-6476fdc549-wdqtk                      1/1     Running     1 (11m ago)   12m
init-get-credentials-sqdnt                               0/1     Completed   0             12m
init-set-aws-iam-b9qck                                   0/1     Completed   0             12m

% helm ls -n castai-agent
NAME      	NAMESPACE   	REVISION	UPDATED                              	STATUS  	CHART           	APP VERSION
castai-aio	castai-agent	1       	2025-07-14 13:28:02.278255 +0200 CEST	deployed	castai-aio-0.0.1	           
```
NOTE: both jobs needs to be completed. 

### Example Anywhere (WOOP only)
custom values file: 
```
---
global:
  apiKey: "YOUR_CASTAI_API_KEY"

castai-agent: 
  apiKey: "YOUR_CASTAI_API_KEY"
  provider: anywhere
  additionalEnv:
    ANYWHERE_CLUSTER_NAME=YOUR_CLUSTER_NAME

castai-spot-handler:
  enabled: false
```

outcome:
```
% kubectl get po -n castai-agent
NAME                                                     READY   STATUS      RESTARTS      AGE
castai-agent-84b8cfb977-stwff                            2/2     Running     0             42s
castai-agent-84b8cfb977-xwjfx                            2/2     Running     0             42s
castai-agent-cpvpa-77d4c7ccc-rxd94                       1/1     Running     0             76s
castai-aio-castai-workload-autoscaler-5c5955c594-6fqzj   1/1     Running     0             96s
castai-aio-castai-workload-autoscaler-5c5955c594-t5r9j   1/1     Running     1 (21s ago)   96s
castai-cluster-controller-6f644b5bd4-dv5sx               2/2     Running     0             96s
castai-cluster-controller-6f644b5bd4-zcvbl               2/2     Running     0             96s
castai-pod-mutator-6bb4d59954-scnw8                      0/1     Pending     0             96s
castai-pod-mutator-6bb4d59954-vm7t5                      1/1     Running     1 (16s ago)   96s
init-get-credentials-sqcmb                               0/1     Completed   0             76s

% helm list -n castai-agent
NAME      	NAMESPACE   	REVISION	UPDATED                              	STATUS  	CHART           	APP VERSION
castai-aio	castai-agent	1       	2025-07-14 13:43:34.164641 +0200 CEST	deployed	castai-aio-0.0.1	                      
```