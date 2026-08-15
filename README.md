# Kubernetes Attune Pack

This production-oriented pack modernizes the Apache-2.0 StackStorm Exchange
Kubernetes pack at revision `d6a52dbf72de7d3e034914299d3ac670d0532c38`
(`v1.0.1`). It replaces 367 generated legacy actions and 33 stale sensors with
31 curated actions backed by Kubernetes API discovery and the maintained
Python client `36.0.3` for Kubernetes 1.36. See [SOURCE.md](SOURCE.md).

Only stable APIs are selected directly: `v1`, `apps/v1`, and `batch/v1`.
Generic reads have an exact non-secret GA allowlist. There are no sensors,
ThirdPartyResources, alpha/beta APIs, pod exec, attach, port-forward, arbitrary
proxy, impersonation, unrestricted generic mutation, or cross-namespace list.

## Requirements

- Python 3.10 or newer on the selected Attune worker.
- Network access from the worker to an HTTPS Kubernetes API server.
- An encrypted, pack-owned Attune Key, normally `kubernetes.credentials`.
- Kubernetes RBAC limited to the actions and namespaces that worker needs.

The pack never creates or elevates RBAC. Kubernetes authorization and admission
remain authoritative. Workload writes additionally reject host namespaces,
hostPath, hostPort, privileged containers, added Linux capabilities, explicit
privilege escalation, and service accounts outside credential policy.

## Credentials

Actions accept only an Attune Key reference beginning with `kubernetes.`. They cannot override server,
cluster, context, bearer token, client certificate, or CA material.

Direct token credentials:

```json
{
  "server": "https://api.cluster.example:6443",
  "token": "REDACTED_BEARER_TOKEN",
  "context": "production",
  "cluster_name": "production-us-east",
  "ca_cert": "-----BEGIN CERTIFICATE-----\nREDACTED_CA\n-----END CERTIFICATE-----",
  "default_namespace": "apps",
  "allowed_namespaces": ["apps", "jobs"],
  "allowed_service_accounts": ["default", "deployer"]
}
```

For mTLS, replace `token` with `client_cert` and `client_key`. A token and mTLS
may also be used together when the API server requires both.

Kubeconfig credentials:

```json
{
  "kubeconfig": "apiVersion: v1\nkind: Config\n...",
  "context": "production",
  "default_namespace": "apps",
  "allowed_namespaces": ["apps"]
}
```

The selected kubeconfig must use an HTTPS server, embedded
`certificate-authority-data`, `client-certificate-data`, `client-key-data`, or
a literal token. Relative/absolute credential files, `tokenFile`, exec and auth
provider plugins, username/password auth, proxy URLs, impersonation fields, and
`insecure-skip-tls-verify` are rejected. A context and cluster identity are
always required and returned in action metadata.

TLS and hostname verification are always enabled. Embedded CA/client material
is decoded into mode-0600 files under a mode-0700 temporary directory only for
the lifetime of one action. Cleanup runs when the API client closes. Worker
temporary storage should still be encrypted because a process hard-kill can
bypass application cleanup. Client HTTP retries are disabled, so mutations are
never retried by the pack.

## Actions

| Actions | Scope |
|---|---|
| `cluster_version`, `node_get`, `node_list` | Cluster and Node reads |
| `namespace_get`, `namespace_list`, `namespace_create`, `namespace_delete` | Namespace lifecycle |
| `workload_get`, `workload_list`, `workload_apply`, `workload_patch`, `workload_scale`, `workload_delete` | Deployments, StatefulSets, DaemonSets; DaemonSet scale is explicitly rejected |
| `batch_get`, `batch_list`, `batch_apply`, `batch_patch`, `batch_delete` | Jobs and CronJobs |
| `core_get`, `core_list`, `core_apply`, `core_patch`, `core_delete` | Services and ConfigMaps |
| `secret_write` | Guarded Secret create/update from a second Attune Key |
| `pod_get`, `pod_list`, `pod_logs` | Pod reads and bounded, non-following logs |
| `rollout_status`, `rollout_restart` | Bounded rollout watch and confirmed restart |
| `generic_get`, `generic_list` | Allowlisted discovery-backed non-secret reads |

All contracts are flat JSON objects delivered on stdin. Results use:

```json
{
  "operation": "list",
  "data": {
    "items": [],
    "continue_token": null,
    "resource_version": "12345",
    "remaining_item_count": null
  },
  "meta": {
    "context": "production",
    "cluster": "production-us-east",
    "namespace": "apps",
    "api_version": "apps/v1",
    "kind": "Deployment",
    "dry_run": false,
    "request_timeout_seconds": 30
  }
}
```

Lists default to 100 objects and cap each page at 500. Callers pass the opaque
`continue_token` to fetch the next consistent page. Serialized outputs default
to a 1 MiB cap and may be raised only to 4 MiB. Pod logs are server-limited,
never follow, and have independent line, time, and byte bounds.

## Mutations

Create-or-apply uses Kubernetes server-side apply with the fixed field manager
`attune-kubernetes`. `force_conflicts` defaults to false; setting it true is an
explicit request to take ownership from another manager. Patch uses JSON merge
patch. Patch, scale, restart, delete, and Secret update accept or require a
`resource_version` precondition as documented by their contracts; HTTP 409 is
returned as a redacted conflict error. Every mutation supports `dry_run`.

Delete requires `confirm` to equal `namespace/name`, or just `name` for a
Namespace. Restart requires `namespace/kind/name`. Deletion propagation is
explicitly one of `Background`, `Foreground`, or `Orphan`, with bounded grace.
There are no automatic mutation retries.

`secret_write` requires a separate Attune Key with this shape:

```json
{
  "type": "Opaque",
  "string_data": {"username": "REDACTED", "password": "REDACTED"},
  "data": {"binary.dat": "BASE64_VALUE"}
}
```

Its action input contains no Secret payload. Update requires the current
resourceVersion. The response is projected to identity metadata before output;
Secret `data` and `stringData` are never returned. API response bodies and
transport exception text are never propagated in errors.

## Generic Reads

Generic access is not arbitrary. The exact `(apiVersion, kind)` pair must be in
the internal allowlist: ReplicaSet, HorizontalPodAutoscaler, Ingress,
NetworkPolicy, PodDisruptionBudget, or StorageClass on their listed GA API.
Discovery must independently confirm identity, namespaced scope, and the read
verb. Secret and credential-bearing resources are not eligible.

## Timeouts

Every API request has a 1-300 second transport timeout. Rollout status performs
an initial read and then one API watch bounded to 1-900 seconds. The server-side
watch timeout disables the Python watch helper's resume retry, and the socket
read timeout is independently bounded. A completed initial read opens no watch.

## Validation

```bash
python3 -m unittest discover -s tests -v
attune --output json pack check /home/david/Codebase/attune-packs/kubernetes
attune pack test /home/david/Codebase/attune-packs/kubernetes --detailed
```

Tests use deterministic fake discovery/resources and make no cluster calls.
Live validation remains deployment-specific because Kubernetes RBAC, admission
policy, API aggregation, workload policy, PKI, and network topology vary.

## License

The verified upstream Apache License 2.0 text is included in [LICENSE](LICENSE).
Attribution and substantial modification details are in [NOTICE](NOTICE).
