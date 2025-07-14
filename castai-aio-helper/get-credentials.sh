#!/bin/bash
if [ -n "${DEBUG}" ] ; then
    set -x
fi

echo "Getting new credentials for cluster ${CASTAI_CLUSTER_ID}."
response=$(curl --retry 5 --retry-all-errors -X 'GET' \
  -H 'Accept: application/json' \
  -H 'X-API-Key: '${CASTAI_API_TOKEN}'' \
  "${CASTAI_API_URL}/v1/kubernetes/external-clusters/${CASTAI_CLUSTER_ID}/credentials-script")

if [ "$(echo "${response}" | jq .error.message)" != "null" ]; then
  echo "Received error: ${response}"
  exit 1
fi

CASTAI_API_TOKEN=$(echo "${response}" | jq -r .script)
if [ -z ${CASTAI_API_TOKEN} ]; then
  echo "error getting CASTAI_API_TOKEN: ${response}"
  exit 1
fi
# Check if response includes onboarding script
echo ${CASTAI_API_TOKEN} | grep onboarding >/dev/null
if [ $? -eq 0 ] ; then
    CASTAI_API_TOKEN=$(echo ${CASTAI_API_TOKEN}| tr ' ' '\n' | grep '^CASTAI_API_TOKEN=' | cut -d= -f2-)
fi

echo "Creating Kubernetes secret '${SECRET_NAME}' in namespace ${NAMESPACE}..."
kubectl delete secret ${SECRET_NAME} --ignore-not-found -n "${NAMESPACE}"

kubectl create secret generic ${SECRET_NAME} \
  --from-literal=API_KEY="${CASTAI_API_TOKEN}" \
  --from-literal=CLUSTER_ID="${CASTAI_CLUSTER_ID}" \
  -n "${NAMESPACE}"