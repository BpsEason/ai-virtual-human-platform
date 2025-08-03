#!/bin/bash
echo "部署 Helm Chart..."
helm upgrade --install my-app ./kubernetes/helm --set image.tag=latest --namespace my-namespace --create-namespace
