# TDX quote broker on GKE

## Prerequisites

- A GKE Standard cluster with a Ready C3 Intel TDX node.
- Docker Buildx, `gcloud`, `kubectl`, and `jq`.
- An Artifact Registry Docker repository that GKE nodes can read.
- An Intel Trust Authority configuration file for the test.
- Permission to create a DaemonSet and ServiceAccount in `kube-system`.

The broker attests the TDX node, not an individual Pod. The DaemonSet requires
root, `CAP_SYS_ADMIN`, an unconfined AppArmor profile, and the configfs
`hostPath` shown in the supplied manifest.

The broker socket accepts requests from any process that can connect to it and
permits callers to supply arbitrary REPORTDATA for a node quote. Restrict the
broker socket `hostPath` to approved workloads with cluster admission policy;
permission to mount that path is the authorization boundary.

Set the target values from the repository root:

```bash
set -euo pipefail

export PROJECT_ID=your-project-id
export CLUSTER_NAME=your-cluster
export CLUSTER_LOCATION=us-central1-a
export REGION=us-central1
export REPOSITORY=your-repository
export TAG=tdx-quote-broker-test
export BROKER_IMAGE="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPOSITORY}/tdx-quote-broker"
export NGINX_IMAGE="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPOSITORY}/tdx-nginx-test"
export ITA_CONFIG=/absolute/path/to/config.json
export TEST_NAMESPACE=tdx-quote-broker-test

gcloud container clusters get-credentials "${CLUSTER_NAME}" \
  --project "${PROJECT_ID}" \
  --location "${CLUSTER_LOCATION}"
gcloud auth configure-docker "${REGION}-docker.pkg.dev"

kubectl get nodes \
  -L cloud.google.com/gke-confidential-nodes-instance-type \
  -L cloud.google.com/machine-family
```

Continue only when a Ready node reports `TDX` and machine family `c3`.

## Build

```bash
docker buildx build \
  --platform linux/amd64 \
  --push \
  --file tdx-quote-broker/Dockerfile \
  --tag "${BROKER_IMAGE}:${TAG}" \
  .

docker buildx build \
  --platform linux/amd64 \
  --push \
  --file tdx-quote-broker/nginx-test.Dockerfile \
  --tag "${NGINX_IMAGE}:${TAG}" \
  .

export BROKER_DIGEST="$(gcloud artifacts docker images describe "${BROKER_IMAGE}:${TAG}" \
  --project "${PROJECT_ID}" \
  --format='value(image_summary.digest)')"
export NGINX_DIGEST="$(gcloud artifacts docker images describe "${NGINX_IMAGE}:${TAG}" \
  --project "${PROJECT_ID}" \
  --format='value(image_summary.digest)')"
printf '%s\n' "${BROKER_DIGEST}" "${NGINX_DIGEST}" | \
  grep -Ec '^sha256:[0-9a-f]{64}$' | grep -Fx 2
export PINNED_BROKER_IMAGE="${BROKER_IMAGE}@${BROKER_DIGEST}"
export PINNED_NGINX_IMAGE="${NGINX_IMAGE}@${NGINX_DIGEST}"
```

## Deploy

Create temporary manifests that use the immutable image digest:

```bash
export BROKER_IMAGE_PLACEHOLDER='example.invalid/tdx-quote-broker@sha256:0000000000000000000000000000000000000000000000000000000000000000'
export NGINX_IMAGE_PLACEHOLDER='example.invalid/tdx-nginx-test@sha256:0000000000000000000000000000000000000000000000000000000000000000'

sed "s#${BROKER_IMAGE_PLACEHOLDER}#${PINNED_BROKER_IMAGE}#" \
  tdx-quote-broker/deploy/gke-daemonset.yaml \
  > /tmp/tdx-quote-broker-daemonset.yaml
sed "s#${NGINX_IMAGE_PLACEHOLDER}#${PINNED_NGINX_IMAGE}#" \
  tdx-quote-broker/deploy/gke-test-pod.yaml \
  > /tmp/tdx-quote-broker-test-pod.yaml

! grep -F example.invalid /tmp/tdx-quote-broker-daemonset.yaml
! grep -F example.invalid /tmp/tdx-quote-broker-test-pod.yaml

kubectl apply --server-side --dry-run=server \
  -f /tmp/tdx-quote-broker-daemonset.yaml
kubectl apply -f /tmp/tdx-quote-broker-daemonset.yaml
kubectl -n kube-system rollout status \
  daemonset/tdx-quote-broker --timeout=5m

BROKER_POD="$(kubectl -n kube-system get pods \
  -l app.kubernetes.io/name=tdx-quote-broker \
  -o jsonpath='{.items[0].metadata.name}')"
kubectl -n kube-system exec "${BROKER_POD}" -- \
  tdx-quote-broker --healthcheck
```

## Test

The configuration file must contain the API URL, portal URL, and API key for the
same Intel Trust Authority region:

```json
{
  "trustauthority_url": "https://portal.trustauthority.intel.com",
  "trustauthority_api_url": "https://api.trustauthority.intel.com",
  "trustauthority_api_key": "REPLACE_WITH_API_KEY"
}
```

Run the supplied non-root NGINX Pod. Its main container accesses the DaemonSet
socket directly, generates a quote, independently obtains and verifies an Intel
Trust Authority token, and then starts NGINX:

```bash
jq -e '
  (.trustauthority_url | type == "string" and length > 0) and
  (.trustauthority_api_url | type == "string" and length > 0) and
  (.trustauthority_api_key | type == "string" and length > 0)
' "${ITA_CONFIG}" >/dev/null

kubectl create namespace "${TEST_NAMESPACE}"
kubectl -n "${TEST_NAMESPACE}" create secret generic ita-tdx-config \
  --from-file=config.json="${ITA_CONFIG}"

kubectl -n "${TEST_NAMESPACE}" apply --server-side --dry-run=server \
  -f /tmp/tdx-quote-broker-test-pod.yaml
kubectl -n "${TEST_NAMESPACE}" apply \
  -f /tmp/tdx-quote-broker-test-pod.yaml
kubectl -n "${TEST_NAMESPACE}" wait \
  --for=condition=Ready \
  pod/nginx-tdx-attestation --timeout=10m

TEST_LOGS="$(kubectl -n "${TEST_NAMESPACE}" logs \
  nginx-tdx-attestation)"
printf '%s\n' "${TEST_LOGS}"
grep -Fx 'Workload UID/GID: 101/101' <<<"${TEST_LOGS}"
grep -Eq '^TDX quote generated: [1-9][0-9]* bytes$' <<<"${TEST_LOGS}"
grep -Eq '^TDX quote SHA-256: [0-9a-f]{64}$' <<<"${TEST_LOGS}"
grep -F 'Token is valid and issued by Intel Trust Authority' <<<"${TEST_LOGS}"
grep -Fx 'E2E_SANITY_PASS' <<<"${TEST_LOGS}"
kubectl -n "${TEST_NAMESPACE}" get pod nginx-tdx-attestation
```

## Cleanup

```bash
kubectl delete namespace "${TEST_NAMESPACE}" --ignore-not-found
kubectl -n kube-system delete \
  daemonset/tdx-quote-broker serviceaccount/tdx-quote-broker \
  --ignore-not-found
rm -f /tmp/tdx-quote-broker-daemonset.yaml \
  /tmp/tdx-quote-broker-test-pod.yaml
```

The empty `/var/run/tdx-quote-broker` directory can remain on each node until
that node is recreated.
