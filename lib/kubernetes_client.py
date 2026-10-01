"""Hardened Kubernetes dynamic-client facade for the curated action surface."""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit


class KubernetesPackError(Exception):
    """An operator-safe error that contains no server or credential data."""


SAFE_GENERIC = {
    ("apps/v1", "ReplicaSet"): True,
    ("autoscaling/v2", "HorizontalPodAutoscaler"): True,
    ("networking.k8s.io/v1", "Ingress"): True,
    ("networking.k8s.io/v1", "NetworkPolicy"): True,
    ("policy/v1", "PodDisruptionBudget"): True,
    ("storage.k8s.io/v1", "StorageClass"): False,
}

WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet"}
BATCH_KINDS = {"Job", "CronJob"}
CORE_KINDS = {"Service", "ConfigMap"}
_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
_SECRET_KEY = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$")
_FIELD_MANAGER = "attune-kubernetes"
_MAX_MANIFEST_BYTES = 512 * 1024

_COMMON_PARAMS = {"credential_key", "request_timeout_seconds", "max_output_bytes"}
_PARAMS = {
    "cluster_version": set(),
    "node_get": {"name"},
    "node_list": {"label_selector", "field_selector", "limit", "continue_token"},
    "namespace_get": {"name"},
    "namespace_list": {"label_selector", "field_selector", "limit", "continue_token"},
    "namespace_create": {"name", "labels", "annotations", "dry_run"},
    "namespace_delete": {
        "name",
        "confirm",
        "propagation_policy",
        "grace_period_seconds",
        "resource_version",
        "dry_run",
    },
    "workload_get": {"kind", "namespace", "name"},
    "workload_list": {
        "kind",
        "namespace",
        "label_selector",
        "field_selector",
        "limit",
        "continue_token",
    },
    "workload_apply": {
        "kind",
        "namespace",
        "name",
        "body",
        "force_conflicts",
        "dry_run",
    },
    "workload_patch": {
        "kind",
        "namespace",
        "name",
        "patch",
        "resource_version",
        "dry_run",
    },
    "workload_scale": {
        "kind",
        "namespace",
        "name",
        "replicas",
        "resource_version",
        "dry_run",
    },
    "workload_delete": {
        "kind",
        "namespace",
        "name",
        "confirm",
        "propagation_policy",
        "grace_period_seconds",
        "resource_version",
        "dry_run",
    },
    "batch_get": {"kind", "namespace", "name"},
    "batch_list": {
        "kind",
        "namespace",
        "label_selector",
        "field_selector",
        "limit",
        "continue_token",
    },
    "batch_apply": {"kind", "namespace", "name", "body", "force_conflicts", "dry_run"},
    "batch_patch": {
        "kind",
        "namespace",
        "name",
        "patch",
        "resource_version",
        "dry_run",
    },
    "batch_delete": {
        "kind",
        "namespace",
        "name",
        "confirm",
        "propagation_policy",
        "grace_period_seconds",
        "resource_version",
        "dry_run",
    },
    "core_get": {"kind", "namespace", "name"},
    "core_list": {
        "kind",
        "namespace",
        "label_selector",
        "field_selector",
        "limit",
        "continue_token",
    },
    "core_apply": {"kind", "namespace", "name", "body", "force_conflicts", "dry_run"},
    "core_patch": {"kind", "namespace", "name", "patch", "resource_version", "dry_run"},
    "core_delete": {
        "kind",
        "namespace",
        "name",
        "confirm",
        "propagation_policy",
        "grace_period_seconds",
        "resource_version",
        "dry_run",
    },
    "secret_write": {
        "namespace",
        "name",
        "secret_key",
        "mode",
        "resource_version",
        "confirm",
        "dry_run",
    },
    "pod_get": {"namespace", "name"},
    "pod_list": {
        "namespace",
        "label_selector",
        "field_selector",
        "limit",
        "continue_token",
    },
    "pod_logs": {
        "namespace",
        "name",
        "container",
        "previous",
        "tail_lines",
        "since_seconds",
        "timestamps",
        "max_log_bytes",
    },
    "rollout_status": {"kind", "namespace", "name", "watch_timeout_seconds"},
    "rollout_restart": {
        "kind",
        "namespace",
        "name",
        "resource_version",
        "confirm",
        "dry_run",
    },
    "generic_get": {"api_version", "kind", "namespace", "name"},
    "generic_list": {
        "api_version",
        "kind",
        "namespace",
        "label_selector",
        "field_selector",
        "limit",
        "continue_token",
    },
}


def _plain(value: Any) -> Any:
    if callable(getattr(value, "to_dict", None)):
        value = value.to_dict()
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _strip_managed_fields(value: Any) -> Any:
    value = _plain(value)
    if isinstance(value, dict):
        metadata = value.get("metadata")
        if isinstance(metadata, dict):
            metadata.pop("managedFields", None)
            metadata.pop("managed_fields", None)
        return {key: _strip_managed_fields(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_strip_managed_fields(item) for item in value]
    return value


def _bounded(value: Any, maximum: int, label: str) -> Any:
    encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode()
    if len(encoded) > maximum:
        raise KubernetesPackError(f"{label} exceeds the configured output limit")
    return value


def _int(
    params: dict[str, Any], name: str, default: int, minimum: int, maximum: int
) -> int:
    value = params.get(name, default)
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise KubernetesPackError(
            f"{name} must be an integer from {minimum} through {maximum}"
        )
    return value


def _bool(params: dict[str, Any], name: str, default: bool = False) -> bool:
    value = params.get(name, default)
    if not isinstance(value, bool):
        raise KubernetesPackError(f"{name} must be a boolean")
    return value


def _name(value: Any, label: str = "name") -> str:
    if not isinstance(value, str) or not _NAME.fullmatch(value) or ".." in value:
        raise KubernetesPackError(f"{label} must be a valid lowercase Kubernetes name")
    return value


def _selector(params: dict[str, Any], name: str) -> str | None:
    value = params.get(name)
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 1024
        or "\n" in value
        or "\r" in value
    ):
        raise KubernetesPackError(
            f"{name} must be a non-empty selector of at most 1024 characters"
        )
    return value


def _resource_version(value: Any) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 256
        or "\n" in value
        or "\r" in value
    ):
        raise KubernetesPackError("resource_version is invalid")
    return value


def _continue(params: dict[str, Any]) -> str | None:
    value = params.get("continue_token")
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 4096
        or "\n" in value
        or "\r" in value
    ):
        raise KubernetesPackError("continue_token is invalid")
    return value


def _json_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise KubernetesPackError(f"{label} must be a JSON object")
    try:
        encoded = json.dumps(value, allow_nan=False, separators=(",", ":")).encode()
    except (TypeError, ValueError):
        raise KubernetesPackError(f"{label} must contain only JSON values") from None
    if len(encoded) > _MAX_MANIFEST_BYTES:
        raise KubernetesPackError(f"{label} exceeds 512 KiB")
    return json.loads(encoded)


def _metadata(result: Any) -> dict[str, Any]:
    body = _plain(result)
    metadata = body.get("metadata", {}) if isinstance(body, dict) else {}
    if not isinstance(metadata, dict):
        metadata = {}
    return {
        "name": metadata.get("name"),
        "namespace": metadata.get("namespace"),
        "uid": metadata.get("uid"),
        "resource_version": metadata.get(
            "resourceVersion", metadata.get("resource_version")
        ),
        "generation": metadata.get("generation"),
        "creation_timestamp": metadata.get(
            "creationTimestamp", metadata.get("creation_timestamp")
        ),
    }


def _api_error(exc: Exception) -> KubernetesPackError:
    status = getattr(exc, "status", None)
    labels = {
        400: "bad request",
        401: "unauthorized",
        403: "forbidden",
        404: "not found",
        409: "conflict",
        410: "resource version expired",
        422: "rejected",
        429: "rate limited",
    }
    if isinstance(status, int):
        return KubernetesPackError(
            f"Kubernetes API request failed (HTTP {status} {labels.get(status, 'error')})"
        )
    return KubernetesPackError(
        f"Kubernetes client request failed ({type(exc).__name__})"
    )


def _call(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except KubernetesPackError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _api_error(exc) from None


def _fetch_key(reference: str) -> dict[str, Any]:
    if (
        not isinstance(reference, str)
        or not reference.startswith("pack.kubernetes.")
        or len(reference) > 255
        or "\n" in reference
        or "\r" in reference
    ):
        raise KubernetesPackError(
            "Attune Key reference must be in the kubernetes pack namespace"
        )
    try:
        import attune
        from attune.api_client.api.secrets import get_key

        response = get_key.sync_detailed(reference, client=attune.context.client)
        if response.status_code != 200 or response.parsed is None:
            raise RuntimeError("key lookup failed")
        value = response.parsed.data.value
        value = json.loads(value) if isinstance(value, str) else value
        if not isinstance(value, dict):
            raise TypeError("key value is not an object")
        return value
    except KubernetesPackError:
        raise
    except Exception:  # noqa: BLE001
        raise KubernetesPackError("Attune Key lookup failed") from None


def _decode_data(value: Any, label: str, maximum: int = 1024 * 1024) -> bytes:
    if not isinstance(value, str) or len(value) > maximum * 2:
        raise KubernetesPackError(f"{label} is invalid")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise KubernetesPackError(f"{label} is not valid base64") from None
    if len(decoded) > maximum:
        raise KubernetesPackError(f"{label} exceeds its size limit")
    return decoded


def _parse_kubeconfig(raw: Any, requested_context: Any) -> dict[str, Any]:
    if not isinstance(raw, str) or not raw or len(raw.encode()) > 1024 * 1024:
        raise KubernetesPackError(
            "kubeconfig must be a non-empty string of at most 1 MiB"
        )
    try:
        import yaml

        class KubeconfigLoader(yaml.SafeLoader):
            def compose_node(self, parent, index):
                if self.check_event(yaml.AliasEvent):
                    raise yaml.YAMLError("aliases are not permitted")
                return super().compose_node(parent, index)

        def unique_mapping(loader, node, deep=False):
            mapping = {}
            for key_node, value_node in node.value:
                key = loader.construct_object(key_node, deep=deep)
                if key in mapping:
                    raise yaml.YAMLError("duplicate mapping key")
                mapping[key] = loader.construct_object(value_node, deep=deep)
            return mapping

        KubeconfigLoader.add_constructor(
            yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping
        )
        document = yaml.load(raw, Loader=KubeconfigLoader)
    except Exception:  # noqa: BLE001
        raise KubernetesPackError("kubeconfig is not valid safe YAML") from None
    if (
        not isinstance(document, dict)
        or document.get("apiVersion") != "v1"
        or document.get("kind") != "Config"
    ):
        raise KubernetesPackError("kubeconfig must be a v1 Config object")
    context_name = requested_context or document.get("current-context")
    if not isinstance(context_name, str) or not context_name:
        raise KubernetesPackError("a kubeconfig context is required")

    def selected(collection: str, name: str) -> dict[str, Any]:
        values = document.get(collection)
        if not isinstance(values, list):
            raise KubernetesPackError(f"kubeconfig {collection} must be a list")
        matches = [
            item
            for item in values
            if isinstance(item, dict) and item.get("name") == name
        ]
        key = {"contexts": "context", "clusters": "cluster", "users": "user"}[
            collection
        ]
        if len(matches) != 1 or not isinstance(matches[0].get(key), dict):
            raise KubernetesPackError(
                f"kubeconfig {collection[:-1]} selection is invalid"
            )
        return matches[0][key]

    context = selected("contexts", context_name)
    cluster_name = context.get("cluster")
    user_name = context.get("user")
    if not isinstance(cluster_name, str) or not isinstance(user_name, str):
        raise KubernetesPackError("kubeconfig context must select one cluster and user")
    cluster = selected("clusters", cluster_name)
    user = selected("users", user_name)
    forbidden_cluster = {
        "certificate-authority",
        "insecure-skip-tls-verify",
        "proxy-url",
    } & set(cluster)
    forbidden_user = {
        "client-certificate",
        "client-key",
        "tokenFile",
        "exec",
        "auth-provider",
        "username",
        "password",
        "as",
        "as-groups",
    } & set(user)
    if forbidden_cluster or forbidden_user:
        raise KubernetesPackError(
            "kubeconfig contains file, plugin, proxy, impersonation, basic-auth, or insecure TLS settings"
        )
    return {
        "server": cluster.get("server"),
        "ca_bytes": _decode_data(
            cluster["certificate-authority-data"], "certificate-authority-data"
        )
        if cluster.get("certificate-authority-data")
        else None,
        "token": user.get("token"),
        "cert_bytes": _decode_data(
            user["client-certificate-data"], "client-certificate-data"
        )
        if user.get("client-certificate-data")
        else None,
        "key_bytes": _decode_data(user["client-key-data"], "client-key-data")
        if user.get("client-key-data")
        else None,
        "context": context_name,
        "cluster": cluster_name,
        "namespace": context.get("namespace"),
        "tls_server_name": cluster.get("tls-server-name"),
    }


def _credential(settings: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "kubeconfig",
        "server",
        "token",
        "ca_cert",
        "client_cert",
        "client_key",
        "context",
        "cluster_name",
        "default_namespace",
        "allowed_namespaces",
        "allowed_service_accounts",
    }
    if not isinstance(settings, dict) or set(settings) - allowed:
        raise KubernetesPackError("credential Key contains unsupported settings")
    if bool(settings.get("kubeconfig")) == bool(settings.get("server")):
        raise KubernetesPackError(
            "credential Key must contain exactly one of kubeconfig or server"
        )
    if settings.get("kubeconfig"):
        parsed = _parse_kubeconfig(settings["kubeconfig"], settings.get("context"))
    else:
        for field in ("ca_cert", "client_cert", "client_key"):
            if settings.get(field) is not None and not isinstance(settings[field], str):
                raise KubernetesPackError(f"{field} must be a string")
            if (
                isinstance(settings.get(field), str)
                and len(settings[field].encode()) > 1024 * 1024
            ):
                raise KubernetesPackError(f"{field} exceeds 1 MiB")
        parsed = {
            "server": settings.get("server"),
            "token": settings.get("token"),
            "ca_bytes": settings.get("ca_cert", "").encode() or None,
            "cert_bytes": settings.get("client_cert", "").encode() or None,
            "key_bytes": settings.get("client_key", "").encode() or None,
            "context": settings.get("context"),
            "cluster": settings.get("cluster_name"),
            "namespace": None,
            "tls_server_name": None,
        }
    url = urlsplit(parsed.get("server") or "")
    if (
        url.scheme != "https"
        or not url.hostname
        or url.username
        or url.password
        or url.query
        or url.fragment
        or url.path not in ("", "/")
    ):
        raise KubernetesPackError(
            "Kubernetes server must be an HTTPS origin without credentials or a path"
        )
    if (
        not isinstance(parsed.get("context"), str)
        or not parsed["context"]
        or not isinstance(parsed.get("cluster"), str)
        or not parsed["cluster"]
    ):
        raise KubernetesPackError("credential Key must identify context and cluster")
    token = parsed.get("token")
    if token is not None and (
        not isinstance(token, str)
        or not token
        or len(token) > 16384
        or "\n" in token
        or "\r" in token
    ):
        raise KubernetesPackError("bearer token is invalid")
    cert, key = parsed.get("cert_bytes"), parsed.get("key_bytes")
    if bool(cert) != bool(key) or not (token or (cert and key)):
        raise KubernetesPackError(
            "credential Key requires a bearer token or client certificate and key"
        )
    default_namespace = settings.get("default_namespace", parsed.get("namespace"))
    if default_namespace is not None:
        default_namespace = _name(default_namespace, "default_namespace")
    namespaces = settings.get("allowed_namespaces")
    if namespaces is not None:
        if not isinstance(namespaces, list) or not namespaces or len(namespaces) > 256:
            raise KubernetesPackError("allowed_namespaces must be a non-empty list")
        namespaces = {_name(item, "allowed namespace") for item in namespaces}
        if default_namespace and default_namespace not in namespaces:
            raise KubernetesPackError("default_namespace is outside allowed_namespaces")
    service_accounts = settings.get("allowed_service_accounts", ["default"])
    if (
        not isinstance(service_accounts, list)
        or not service_accounts
        or len(service_accounts) > 256
    ):
        raise KubernetesPackError("allowed_service_accounts must be a non-empty list")
    parsed.update(
        {
            "default_namespace": default_namespace,
            "allowed_namespaces": namespaces,
            "allowed_service_accounts": {
                _name(item, "allowed service account") for item in service_accounts
            },
        }
    )
    return parsed


def _write_private(directory: str, name: str, content: bytes) -> str:
    path = os.path.join(directory, name)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    return path


@contextmanager
def _connection(settings: dict[str, Any], request_timeout: int = 30):
    parsed = _credential(settings)
    try:
        from kubernetes import client
        from kubernetes.dynamic import DynamicClient
    except ImportError:
        raise KubernetesPackError("kubernetes Python client is not installed") from None
    with tempfile.TemporaryDirectory(prefix="attune-kubernetes-") as directory:
        os.chmod(directory, 0o700)
        configuration = client.Configuration(host=parsed["server"])
        configuration.verify_ssl = True
        configuration.assert_hostname = True
        configuration.proxy = None
        configuration.no_proxy = None
        configuration.retries = 0
        configuration.connection_pool_maxsize = 4
        if parsed.get("tls_server_name"):
            configuration.tls_server_name = parsed["tls_server_name"]
        if parsed.get("ca_bytes"):
            configuration.ssl_ca_cert = _write_private(
                directory, "ca.crt", parsed["ca_bytes"]
            )
        if parsed.get("cert_bytes"):
            configuration.cert_file = _write_private(
                directory, "client.crt", parsed["cert_bytes"]
            )
            configuration.key_file = _write_private(
                directory, "client.key", parsed["key_bytes"]
            )
        if parsed.get("token"):
            configuration.api_key["BearerToken"] = parsed["token"]
            configuration.api_key_prefix["BearerToken"] = "Bearer"
        api_client = client.ApiClient(configuration)

        class BoundedDynamicClient(DynamicClient):
            def request(self, method, path, body=None, **params):
                params.setdefault(
                    "_request_timeout", (min(10, request_timeout), request_timeout)
                )
                return super().request(method, path, body=body, **params)

        connection = {
            "dynamic": BoundedDynamicClient(api_client),
            "core": client.CoreV1Api(api_client),
            "version": client.VersionApi(api_client),
            "api_client": api_client,
            **parsed,
        }
        try:
            yield connection
        finally:
            api_client.close()


def _validate_workload_security(
    body: dict[str, Any], allowed_service_accounts: set[str]
) -> None:
    kind = body.get("kind")
    spec = body.get("spec", {})
    if not isinstance(spec, dict):
        raise KubernetesPackError("workload spec must be a JSON object")
    try:
        if kind == "CronJob":
            pod = (
                spec.get("jobTemplate", {})
                .get("spec", {})
                .get("template", {})
                .get("spec", {})
            )
        elif kind in WORKLOAD_KINDS | {"Job"}:
            pod = spec.get("template", {}).get("spec", {})
        else:
            return
    except AttributeError:
        raise KubernetesPackError(
            "workload pod template must contain JSON objects"
        ) from None
    if not isinstance(pod, dict):
        raise KubernetesPackError("workload pod spec must be a JSON object")
    service_account = pod.get(
        "serviceAccountName", pod.get("serviceAccount", "default")
    )
    if service_account not in allowed_service_accounts:
        raise KubernetesPackError(
            "workload service account is not allowed by the credential policy"
        )
    if any(pod.get(field) is True for field in ("hostNetwork", "hostPID", "hostIPC")):
        raise KubernetesPackError("workload host namespace access is not allowed")
    pod_security = pod.get("securityContext", {})
    if (
        isinstance(pod_security, dict)
        and isinstance(pod_security.get("windowsOptions"), dict)
        and pod_security["windowsOptions"].get("hostProcess") is True
    ):
        raise KubernetesPackError("Windows HostProcess containers are not allowed")
    volumes = pod.get("volumes", [])
    if isinstance(volumes, list) and any(
        isinstance(volume, dict) and "hostPath" in volume for volume in volumes
    ):
        raise KubernetesPackError("workload hostPath volumes are not allowed")
    containers = []
    for field in ("containers", "initContainers", "ephemeralContainers"):
        value = pod.get(field, [])
        if isinstance(value, list):
            containers.extend(item for item in value if isinstance(item, dict))
    for container in containers:
        security = container.get("securityContext", {})
        if security is None:
            security = {}
        if not isinstance(security, dict):
            raise KubernetesPackError("container securityContext must be a JSON object")
        capabilities = (
            security.get("capabilities", {}) if isinstance(security, dict) else {}
        )
        ports = container.get("ports", [])
        if (
            security.get("privileged") is True
            or security.get("allowPrivilegeEscalation") is True
        ):
            raise KubernetesPackError("privileged containers are not allowed")
        windows = security.get("windowsOptions", {})
        if (
            security.get("procMount") == "Unmasked"
            or isinstance(windows, dict)
            and windows.get("hostProcess") is True
        ):
            raise KubernetesPackError(
                "unmasked proc or Windows HostProcess access is not allowed"
            )
        if isinstance(capabilities, dict) and capabilities.get("add"):
            raise KubernetesPackError("adding Linux capabilities is not allowed")
        if isinstance(ports, list) and any(
            isinstance(port, dict) and port.get("hostPort") for port in ports
        ):
            raise KubernetesPackError("container host ports are not allowed")


class KubernetesService:
    def __init__(
        self, connection: dict[str, Any], request_timeout: int, max_output: int
    ):
        self.connection = connection
        self.dynamic = connection["dynamic"]
        self.request_timeout = request_timeout
        self.max_output = max_output

    @property
    def timeout(self) -> tuple[int, int]:
        return (min(10, self.request_timeout), self.request_timeout)

    def namespace(self, requested: Any, required: bool = True) -> str | None:
        value = (
            requested
            if requested is not None
            else self.connection.get("default_namespace")
        )
        if value is None and required:
            raise KubernetesPackError(
                "namespace is required because the credential has no default_namespace"
            )
        if value is None:
            return None
        value = _name(value, "namespace")
        allowed = self.connection.get("allowed_namespaces")
        if allowed is not None and value not in allowed:
            raise KubernetesPackError("namespace is outside the credential allowlist")
        return value

    def meta(
        self,
        api_version: str | None = None,
        kind: str | None = None,
        namespace: str | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        return {
            "context": self.connection["context"],
            "cluster": self.connection["cluster"],
            "namespace": namespace,
            "api_version": api_version,
            "kind": kind,
            "dry_run": dry_run,
            "request_timeout_seconds": self.request_timeout,
        }

    def resource(self, api_version: str, kind: str, namespaced: bool, verb: str):
        resource = _call(self.dynamic.resources.get, api_version=api_version, kind=kind)
        discovered_version = getattr(resource, "group_version", None)
        if (
            discovered_version != api_version
            or getattr(resource, "kind", None) != kind
            or bool(getattr(resource, "namespaced", None)) != namespaced
        ):
            raise KubernetesPackError(
                "discovery returned an unexpected resource identity or scope"
            )
        verbs = getattr(resource, "verbs", None)
        if verbs is not None and verb not in verbs:
            raise KubernetesPackError(f"discovered resource does not support {verb}")
        return resource

    def get(
        self, api_version: str, kind: str, namespace: str | None, name: str
    ) -> dict[str, Any]:
        resource = self.resource(api_version, kind, namespace is not None, "get")
        result = _call(
            resource.get, name=name, namespace=namespace, _request_timeout=self.timeout
        )
        return {
            "operation": "get",
            "data": _bounded(
                _strip_managed_fields(result), self.max_output, "API response"
            ),
            "meta": self.meta(api_version, kind, namespace),
        }

    def list(
        self, api_version: str, kind: str, namespace: str | None, params: dict[str, Any]
    ) -> dict[str, Any]:
        resource = self.resource(api_version, kind, namespace is not None, "list")
        result = _call(
            resource.get,
            namespace=namespace,
            label_selector=_selector(params, "label_selector"),
            field_selector=_selector(params, "field_selector"),
            limit=_int(params, "limit", 100, 1, 500),
            _continue=_continue(params),
            _request_timeout=self.timeout,
        )
        body = _strip_managed_fields(result)
        if not isinstance(body, dict) or not isinstance(body.get("items"), list):
            raise KubernetesPackError("Kubernetes list response is malformed")
        metadata = (
            body.get("metadata", {}) if isinstance(body.get("metadata"), dict) else {}
        )
        if (
            kind == "Namespace"
            and self.connection.get("allowed_namespaces") is not None
        ):
            allowed = self.connection["allowed_namespaces"]
            body["items"] = [
                item
                for item in body["items"]
                if item.get("metadata", {}).get("name") in allowed
            ]
        data = {
            "items": body["items"],
            "continue_token": metadata.get("continue", metadata.get("_continue")),
            "resource_version": metadata.get(
                "resourceVersion", metadata.get("resource_version")
            ),
            "remaining_item_count": metadata.get(
                "remainingItemCount", metadata.get("remaining_item_count")
            ),
        }
        return {
            "operation": "list",
            "data": _bounded(data, self.max_output, "API response"),
            "meta": self.meta(api_version, kind, namespace),
        }

    def manifest(
        self, params: dict[str, Any], api_version: str, kind: str, namespace: str
    ) -> dict[str, Any]:
        body = _json_object(params.get("body"), "body")
        if body.get("apiVersion") != api_version or body.get("kind") != kind:
            raise KubernetesPackError(
                "body apiVersion and kind must match the action resource"
            )
        metadata = body.get("metadata")
        if not isinstance(metadata, dict) or metadata.get("name") != params.get("name"):
            raise KubernetesPackError("body metadata.name must match name")
        if metadata.get("namespace", namespace) != namespace:
            raise KubernetesPackError(
                "body metadata.namespace must match the selected namespace"
            )
        metadata["namespace"] = namespace
        forbidden = {
            "generateName",
            "managedFields",
            "uid",
            "selfLink",
            "deletionTimestamp",
            "deletionGracePeriodSeconds",
        } & set(metadata)
        if forbidden or "status" in body:
            raise KubernetesPackError("body contains server-owned metadata or status")
        _validate_workload_security(body, self.connection["allowed_service_accounts"])
        return body

    def apply(
        self, params: dict[str, Any], api_version: str, kind: str, namespace: str
    ) -> dict[str, Any]:
        resource = self.resource(api_version, kind, True, "patch")
        body = self.manifest(params, api_version, kind, namespace)
        dry_run = _bool(params, "dry_run")
        result = _call(
            resource.server_side_apply,
            body=body,
            name=params["name"],
            namespace=namespace,
            field_manager=_FIELD_MANAGER,
            force_conflicts=_bool(params, "force_conflicts"),
            dry_run="All" if dry_run else None,
            _request_timeout=self.timeout,
        )
        return {
            "operation": "apply",
            "data": {"resource": _metadata(result)},
            "meta": self.meta(api_version, kind, namespace, dry_run),
        }

    def patch(
        self, params: dict[str, Any], api_version: str, kind: str, namespace: str
    ) -> dict[str, Any]:
        resource = self.resource(api_version, kind, True, "patch")
        patch = _json_object(params.get("patch"), "patch")
        if any(key in patch for key in ("apiVersion", "kind", "status")):
            raise KubernetesPackError("patch cannot change apiVersion, kind, or status")
        metadata = patch.setdefault("metadata", {})
        if not isinstance(metadata, dict):
            raise KubernetesPackError("patch metadata must be an object")
        if (
            metadata.get("name", params["name"]) != params["name"]
            or metadata.get("namespace", namespace) != namespace
        ):
            raise KubernetesPackError("patch cannot change resource identity")
        if {
            "managedFields",
            "uid",
            "selfLink",
            "deletionTimestamp",
            "deletionGracePeriodSeconds",
        } & set(metadata):
            raise KubernetesPackError("patch contains server-owned metadata")
        resource_version = _resource_version(params.get("resource_version"))
        if resource_version is not None:
            metadata["resourceVersion"] = resource_version
        _validate_workload_security(
            {"kind": kind, "spec": patch.get("spec", {})},
            self.connection["allowed_service_accounts"],
        )
        dry_run = _bool(params, "dry_run")
        result = _call(
            resource.patch,
            body=patch,
            name=params["name"],
            namespace=namespace,
            content_type="application/merge-patch+json",
            dry_run="All" if dry_run else None,
            _request_timeout=self.timeout,
        )
        return {
            "operation": "patch",
            "data": {"resource": _metadata(result)},
            "meta": self.meta(api_version, kind, namespace, dry_run),
        }

    def delete(
        self, params: dict[str, Any], api_version: str, kind: str, namespace: str | None
    ) -> dict[str, Any]:
        name = _name(params.get("name"))
        expected = f"{namespace}/{name}" if namespace else name
        if params.get("confirm") != expected:
            raise KubernetesPackError(f"confirm must exactly equal {expected}")
        policy = params.get("propagation_policy", "Background")
        if policy not in {"Background", "Foreground", "Orphan"}:
            raise KubernetesPackError("propagation_policy is invalid")
        grace = _int(params, "grace_period_seconds", 30, 0, 3600)
        body: dict[str, Any] = {
            "apiVersion": "v1",
            "kind": "DeleteOptions",
            "propagationPolicy": policy,
            "gracePeriodSeconds": grace,
        }
        resource_version = _resource_version(params.get("resource_version"))
        if resource_version is not None:
            body["preconditions"] = {"resourceVersion": resource_version}
        dry_run = _bool(params, "dry_run")
        resource = self.resource(api_version, kind, namespace is not None, "delete")
        result = _call(
            resource.delete,
            name=name,
            namespace=namespace,
            body=body,
            dry_run="All" if dry_run else None,
            _request_timeout=self.timeout,
        )
        return {
            "operation": "delete",
            "data": {
                "accepted": True,
                "resource": _metadata(result),
                "propagation_policy": policy,
            },
            "meta": self.meta(api_version, kind, namespace, dry_run),
        }

    def dispatch(self, operation: str, params: dict[str, Any]) -> dict[str, Any]:
        if operation == "cluster_version":
            result = _call(
                self.connection["version"].get_code, _request_timeout=self.timeout
            )
            return {
                "operation": operation,
                "data": _bounded(_plain(result), self.max_output, "API response"),
                "meta": self.meta(),
            }
        if operation in {"node_get", "namespace_get", "pod_get"}:
            kind = {"node_get": "Node", "namespace_get": "Namespace", "pod_get": "Pod"}[
                operation
            ]
            namespace = (
                self.namespace(params.get("namespace")) if kind == "Pod" else None
            )
            if kind == "Namespace":
                self.namespace(params.get("name"))
            return self.get("v1", kind, namespace, _name(params.get("name")))
        if operation in {"node_list", "namespace_list", "pod_list"}:
            kind = {
                "node_list": "Node",
                "namespace_list": "Namespace",
                "pod_list": "Pod",
            }[operation]
            namespace = (
                self.namespace(params.get("namespace")) if kind == "Pod" else None
            )
            return self.list("v1", kind, namespace, params)
        if operation == "namespace_create":
            name = _name(params.get("name"))
            self.namespace(name)
            body = {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": name}}
            for field in ("labels", "annotations"):
                if params.get(field) is not None:
                    values = _json_object(params[field], field)
                    if not all(
                        isinstance(key, str) and isinstance(value, str)
                        for key, value in values.items()
                    ):
                        raise KubernetesPackError(
                            f"{field} must contain only string values"
                        )
                    body["metadata"][field] = values
            dry_run = _bool(params, "dry_run")
            resource = self.resource("v1", "Namespace", False, "create")
            result = _call(
                resource.create,
                body=body,
                dry_run="All" if dry_run else None,
                _request_timeout=self.timeout,
            )
            return {
                "operation": operation,
                "data": {"resource": _metadata(result)},
                "meta": self.meta("v1", "Namespace", None, dry_run),
            }
        if operation == "namespace_delete":
            self.namespace(params.get("name"))
            return self.delete(params, "v1", "Namespace", None)
        if operation.startswith("workload_"):
            kind = params.get("kind")
            if kind not in WORKLOAD_KINDS:
                raise KubernetesPackError(
                    "kind must be Deployment, StatefulSet, or DaemonSet"
                )
            return self._resource_operation(operation[9:], params, "apps/v1", kind)
        if operation.startswith("batch_"):
            kind = params.get("kind")
            if kind not in BATCH_KINDS:
                raise KubernetesPackError("kind must be Job or CronJob")
            return self._resource_operation(operation[6:], params, "batch/v1", kind)
        if operation.startswith("core_"):
            kind = params.get("kind")
            if kind not in CORE_KINDS:
                raise KubernetesPackError("kind must be Service or ConfigMap")
            return self._resource_operation(operation[5:], params, "v1", kind)
        if operation == "secret_write":
            return self._secret_write(params)
        if operation == "pod_logs":
            return self._pod_logs(params)
        if operation == "rollout_status":
            return self._rollout_status(params)
        if operation == "rollout_restart":
            return self._rollout_restart(params)
        if operation in {"generic_get", "generic_list"}:
            api_version, kind = params.get("api_version"), params.get("kind")
            namespaced = SAFE_GENERIC.get((api_version, kind))
            if namespaced is None:
                raise KubernetesPackError(
                    "resource is not on the safe generic read allowlist"
                )
            namespace = self.namespace(params.get("namespace")) if namespaced else None
            if operation == "generic_get":
                return self.get(api_version, kind, namespace, _name(params.get("name")))
            return self.list(api_version, kind, namespace, params)
        raise KubernetesPackError("unknown Kubernetes action")

    def _resource_operation(
        self, verb: str, params: dict[str, Any], api_version: str, kind: str
    ) -> dict[str, Any]:
        namespace = self.namespace(params.get("namespace"))
        if verb == "get":
            return self.get(api_version, kind, namespace, _name(params.get("name")))
        if verb == "list":
            return self.list(api_version, kind, namespace, params)
        _name(params.get("name"))
        if verb == "apply":
            return self.apply(params, api_version, kind, namespace)
        if verb == "patch":
            return self.patch(params, api_version, kind, namespace)
        if verb == "delete":
            return self.delete(params, api_version, kind, namespace)
        if verb == "scale":
            if kind == "DaemonSet":
                raise KubernetesPackError("DaemonSet has no scale subresource")
            replicas = _int(params, "replicas", 1, 0, 100000)
            resource = self.resource(api_version, kind, True, "get")
            scale = getattr(resource, "scale", None)
            if scale is None or "patch" not in (getattr(scale, "verbs", []) or []):
                raise KubernetesPackError(
                    "discovered resource has no writable scale subresource"
                )
            metadata: dict[str, Any] = {"name": params["name"], "namespace": namespace}
            resource_version = _resource_version(params.get("resource_version"))
            if resource_version is not None:
                metadata["resourceVersion"] = resource_version
            dry_run = _bool(params, "dry_run")
            result = _call(
                scale.patch,
                body={
                    "apiVersion": "autoscaling/v1",
                    "kind": "Scale",
                    "metadata": metadata,
                    "spec": {"replicas": replicas},
                },
                name=params["name"],
                namespace=namespace,
                content_type="application/merge-patch+json",
                dry_run="All" if dry_run else None,
                _request_timeout=self.timeout,
            )
            return {
                "operation": "scale",
                "data": {"resource": _metadata(result), "replicas": replicas},
                "meta": self.meta(api_version, kind, namespace, dry_run),
            }
        raise KubernetesPackError("unsupported resource operation")

    def _secret_write(self, params: dict[str, Any]) -> dict[str, Any]:
        namespace, name = (
            self.namespace(params.get("namespace")),
            _name(params.get("name")),
        )
        if params.get("confirm") != f"{namespace}/{name}":
            raise KubernetesPackError(f"confirm must exactly equal {namespace}/{name}")
        mode = params.get("mode")
        if mode not in {"create", "update"}:
            raise KubernetesPackError("mode must be create or update")
        resource_version = _resource_version(params.get("resource_version"))
        if mode == "update" and resource_version is None:
            raise KubernetesPackError("resource_version is required for secret update")
        secret = _fetch_key(params.get("secret_key", ""))
        if set(secret) - {"type", "data", "string_data"}:
            raise KubernetesPackError("secret payload Key contains unsupported fields")
        body: dict[str, Any] = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": name, "namespace": namespace},
            "type": secret.get("type", "Opaque"),
        }
        if (
            not isinstance(body["type"], str)
            or not body["type"]
            or len(body["type"]) > 253
        ):
            raise KubernetesPackError("secret type is invalid")
        data = secret.get("data", {})
        strings = secret.get("string_data", {})
        if (
            not isinstance(data, dict)
            or not isinstance(strings, dict)
            or not data
            and not strings
        ):
            raise KubernetesPackError("secret payload Key requires data or string_data")
        if len(data) + len(strings) > 256:
            raise KubernetesPackError("secret payload has too many keys")
        for key, value in data.items():
            if not isinstance(key, str) or not _SECRET_KEY.fullmatch(key):
                raise KubernetesPackError("secret data key is invalid")
            _decode_data(value, "secret data value", _MAX_MANIFEST_BYTES)
        for key, value in strings.items():
            if not isinstance(key, str) or not _SECRET_KEY.fullmatch(key):
                raise KubernetesPackError("secret string_data key is invalid")
            if not isinstance(value, str) or len(value.encode()) > _MAX_MANIFEST_BYTES:
                raise KubernetesPackError("secret string_data value is invalid")
        body["data"], body["stringData"] = data, strings
        if len(json.dumps(body).encode()) > _MAX_MANIFEST_BYTES:
            raise KubernetesPackError("secret payload exceeds 512 KiB")
        dry_run = _bool(params, "dry_run")
        resource = self.resource(
            "v1", "Secret", True, "create" if mode == "create" else "update"
        )
        if mode == "update":
            body["metadata"]["resourceVersion"] = resource_version
            result = _call(
                resource.replace,
                body=body,
                name=name,
                namespace=namespace,
                dry_run="All" if dry_run else None,
                _request_timeout=self.timeout,
            )
        else:
            result = _call(
                resource.create,
                body=body,
                namespace=namespace,
                dry_run="All" if dry_run else None,
                _request_timeout=self.timeout,
            )
        # Deliberately project only non-secret metadata from a response that may contain data.
        return {
            "operation": "secret_write",
            "data": {"mode": mode, "resource": _metadata(result)},
            "meta": self.meta("v1", "Secret", namespace, dry_run),
        }

    def _pod_logs(self, params: dict[str, Any]) -> dict[str, Any]:
        namespace, name = (
            self.namespace(params.get("namespace")),
            _name(params.get("name")),
        )
        container = params.get("container")
        if container is not None:
            _name(container, "container")
        maximum = _int(
            params,
            "max_log_bytes",
            min(self.max_output, 1024 * 1024),
            1,
            min(self.max_output, 4 * 1024 * 1024),
        )
        kwargs = {
            "name": name,
            "namespace": namespace,
            "container": container,
            "previous": _bool(params, "previous"),
            "timestamps": _bool(params, "timestamps"),
            "tail_lines": _int(params, "tail_lines", 500, 1, 10000),
            "limit_bytes": maximum,
            "_request_timeout": self.timeout,
        }
        if params.get("since_seconds") is not None:
            kwargs["since_seconds"] = _int(params, "since_seconds", 1, 1, 604800)
        text = _call(self.connection["core"].read_namespaced_pod_log, **kwargs)
        if not isinstance(text, str):
            text = str(text)
        if len(text.encode()) > maximum:
            raise KubernetesPackError("pod logs exceed the configured output limit")
        return {
            "operation": "pod_logs",
            "data": {
                "logs": text,
                "truncated_by_server_limit": len(text.encode()) >= maximum,
            },
            "meta": self.meta("v1", "Pod", namespace),
        }

    def _rollout_summary(self, kind: str, value: Any) -> dict[str, Any]:
        body = _plain(value)
        metadata, spec, status = (
            body.get("metadata", {}),
            body.get("spec", {}),
            body.get("status", {}),
        )
        generation, observed = (
            metadata.get("generation", 0),
            status.get("observedGeneration", status.get("observed_generation", 0)),
        )
        desired = spec.get("replicas", 1)
        if kind == "Deployment":
            complete = (
                observed >= generation
                and status.get("updatedReplicas", 0) == desired
                and status.get("availableReplicas", 0) == desired
                and status.get("unavailableReplicas", 0) == 0
            )
        elif kind == "StatefulSet":
            complete = (
                observed >= generation
                and status.get("updatedReplicas", 0) == desired
                and status.get("readyReplicas", 0) == desired
                and status.get("currentRevision") == status.get("updateRevision")
            )
        else:
            desired = status.get("desiredNumberScheduled", 0)
            complete = (
                observed >= generation
                and status.get("updatedNumberScheduled", 0) == desired
                and status.get("numberAvailable", 0) == desired
                and status.get("numberUnavailable", 0) == 0
            )
        return {
            "complete": bool(complete),
            "generation": generation,
            "observed_generation": observed,
            "desired": desired,
            "status": status,
        }

    def _rollout_status(self, params: dict[str, Any]) -> dict[str, Any]:
        kind = params.get("kind")
        if kind not in WORKLOAD_KINDS:
            raise KubernetesPackError(
                "kind must be Deployment, StatefulSet, or DaemonSet"
            )
        namespace, name = (
            self.namespace(params.get("namespace")),
            _name(params.get("name")),
        )
        watch_timeout = _int(params, "watch_timeout_seconds", 300, 1, 900)
        resource = self.resource("apps/v1", kind, True, "get")
        current = _call(
            resource.get, name=name, namespace=namespace, _request_timeout=self.timeout
        )
        summary = self._rollout_summary(kind, current)
        if not summary["complete"]:
            try:
                from kubernetes import watch

                watcher = watch.Watch()
                stream = watcher.stream(
                    resource.get,
                    namespace=namespace,
                    field_selector=f"metadata.name={name}",
                    resource_version=_metadata(current)["resource_version"],
                    timeout_seconds=watch_timeout,
                    _request_timeout=(
                        min(10, self.request_timeout),
                        watch_timeout + self.request_timeout,
                    ),
                    serialize=False,
                    deserialize=False,
                )
                try:
                    for event in stream:
                        if not isinstance(event, dict) or event.get("type") not in {
                            "ADDED",
                            "MODIFIED",
                        }:
                            continue
                        summary = self._rollout_summary(kind, event.get("object", {}))
                        if summary["complete"]:
                            break
                finally:
                    watcher.stop()
                    stream.close()
            except KubernetesPackError:
                raise
            except Exception as exc:  # noqa: BLE001
                raise _api_error(exc) from None
        return {
            "operation": "rollout_status",
            "data": _bounded(summary, self.max_output, "rollout status"),
            "meta": {
                **self.meta("apps/v1", kind, namespace),
                "watch_timeout_seconds": watch_timeout,
            },
        }

    def _rollout_restart(self, params: dict[str, Any]) -> dict[str, Any]:
        kind = params.get("kind")
        if kind not in WORKLOAD_KINDS:
            raise KubernetesPackError(
                "kind must be Deployment, StatefulSet, or DaemonSet"
            )
        namespace, name = (
            self.namespace(params.get("namespace")),
            _name(params.get("name")),
        )
        if params.get("confirm") != f"{namespace}/{kind}/{name}":
            raise KubernetesPackError(
                f"confirm must exactly equal {namespace}/{kind}/{name}"
            )
        metadata: dict[str, Any] = {}
        resource_version = _resource_version(params.get("resource_version"))
        if resource_version is not None:
            metadata["resourceVersion"] = resource_version
        patch = {
            "metadata": metadata,
            "spec": {
                "template": {
                    "metadata": {
                        "annotations": {
                            "kubectl.kubernetes.io/restartedAt": datetime.now(
                                timezone.utc
                            ).isoformat()
                        }
                    }
                }
            },
        }
        dry_run = _bool(params, "dry_run")
        resource = self.resource("apps/v1", kind, True, "patch")
        result = _call(
            resource.patch,
            body=patch,
            name=name,
            namespace=namespace,
            content_type="application/merge-patch+json",
            dry_run="All" if dry_run else None,
            _request_timeout=self.timeout,
        )
        return {
            "operation": "rollout_restart",
            "data": {"resource": _metadata(result)},
            "meta": self.meta("apps/v1", kind, namespace, dry_run),
        }


def execute_action(operation: str, params: dict[str, Any]) -> dict[str, Any]:
    if operation not in _PARAMS:
        raise KubernetesPackError("unknown Kubernetes action")
    unknown = set(params) - _COMMON_PARAMS - _PARAMS[operation]
    if unknown:
        raise KubernetesPackError("action parameters contain unsupported fields")
    request_timeout = _int(params, "request_timeout_seconds", 30, 1, 300)
    max_output = _int(params, "max_output_bytes", 1024 * 1024, 1024, 4 * 1024 * 1024)
    credential = _fetch_key(params.get("credential_key", "pack.kubernetes.credentials"))
    with _connection(credential, request_timeout) as connection:
        return KubernetesService(connection, request_timeout, max_output).dispatch(
            operation, params
        )
