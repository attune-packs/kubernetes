# Source Verification

- Requirements reference: https://github.com/StackStorm-Exchange/stackstorm-kubernetes
- Version in the verified default-branch manifest: `1.0.1`
- Verified revision: `d6a52dbf72de7d3e034914299d3ac670d0532c38`
- Revision date: `2025-02-19T19:41:30Z`
- Revision signature: verified by GitHub (`valid`)
- Upstream license: Apache License 2.0
- Upstream NOTICE: none at the verified revision
- Upstream inventory: 367 generated action YAML files, 367 Python runners, and 33 sensors
- Upstream stated cluster baseline: Kubernetes 1.4 and 1.5
- Modern API baseline reviewed: Kubernetes `v1.36` documentation on 2026-08-14
- Python client baseline: `kubernetes==36.0.3`, the maintained client matching Kubernetes 1.36

Authoritative references:

- https://kubernetes.io/docs/reference/using-api/api-concepts/
- https://kubernetes.io/docs/reference/using-api/server-side-apply/
- https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/
- https://github.com/kubernetes-client/python/tree/v36.0.3
- https://pypi.org/project/kubernetes/36.0.3/

This pack is a clean, curated adaptation rather than a mechanical port. The
upstream generated API surface, ThirdPartyResource automation, Kubernetes
1.4/1.5 alpha and beta resources, disabled certificate verification, arbitrary
configuration overrides, and all 33 long-running sensors were deliberately
excluded. Runtime discovery verifies exact group/version/kind, scope, and verbs
before each supported operation.

The repository also retains an older historical `v1.8.0` tag at revision
`3897cf1d5039224fe40892b90dce54cdf3251fa2` (2018-10-21). It is not the current
default-branch revision used as this pack's requirements baseline; the verified
default branch identifies itself as `1.0.1`.
