# Overview
vnode-approver is a component of the vnode, which is only used to agree to the CSR request issued by the vnode when the vnode enables the certificate rolling function
# Build
```
docker build -t <镜像仓库地址> .
docker push <镜像仓库地址>
```
# Deploy
```bash
kubectl apply -f deploy.yaml
```
