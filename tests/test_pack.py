from __future__ import annotations

import base64
import importlib.util
import io
import json
import os
import re
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lib import kubernetes_client as client

ACTIONS = {
    "batch_apply",
    "batch_delete",
    "batch_get",
    "batch_list",
    "batch_patch",
    "cluster_version",
    "core_apply",
    "core_delete",
    "core_get",
    "core_list",
    "core_patch",
    "generic_get",
    "generic_list",
    "namespace_create",
    "namespace_delete",
    "namespace_get",
    "namespace_list",
    "node_get",
    "node_list",
    "pod_get",
    "pod_list",
    "pod_logs",
    "rollout_restart",
    "rollout_status",
    "secret_write",
    "workload_apply",
    "workload_delete",
    "workload_get",
    "workload_list",
    "workload_patch",
    "workload_scale",
}


class FakeScale:
    def __init__(self):
        self.verbs = ["get", "patch"]
        self.calls = []

    def patch(self, **kwargs):
        self.calls.append(("patch", kwargs))
        return {
            "metadata": {
                "name": kwargs["name"],
                "namespace": kwargs["namespace"],
                "resourceVersion": "12",
            }
        }


class FakeResource:
    def __init__(self, api_version, kind, namespaced, result=None):
        self.group_version = api_version
        self.kind = kind
        self.namespaced = namespaced
        self.verbs = ["get", "list", "create", "patch", "update", "delete"]
        self.result = result or {
            "metadata": {
                "name": "demo",
                "namespace": "apps",
                "resourceVersion": "11",
                "managedFields": ["private"],
            }
        }
        self.calls = []
        self.scale = FakeScale()

    def get(self, **kwargs):
        self.calls.append(("get", kwargs))
        return self.result

    def create(self, **kwargs):
        self.calls.append(("create", kwargs))
        return self.result

    def server_side_apply(self, **kwargs):
        self.calls.append(("server_side_apply", kwargs))
        return self.result

    def patch(self, **kwargs):
        self.calls.append(("patch", kwargs))
        return self.result

    def replace(self, **kwargs):
        self.calls.append(("replace", kwargs))
        return self.result

    def delete(self, **kwargs):
        self.calls.append(("delete", kwargs))
        return self.result


class FakeDiscovery:
    def __init__(self):
        self.resources = {}
        self.calls = []

    def add(self, resource):
        self.resources[(resource.group_version, resource.kind)] = resource
        return resource

    def get(self, api_version, kind):
        self.calls.append((api_version, kind))
        return self.resources[(api_version, kind)]


class FakeDynamic:
    def __init__(self, discovery):
        self.resources = discovery


class FakeCore:
    def __init__(self):
        self.calls = []

    def read_namespaced_pod_log(self, **kwargs):
        self.calls.append(kwargs)
        return "line one\nline two\n"


class FakeVersion:
    def get_code(self, **kwargs):
        return {"gitVersion": "v1.36.0"}


def service(allowed=None):
    discovery = FakeDiscovery()
    connection = {
        "dynamic": FakeDynamic(discovery),
        "core": FakeCore(),
        "version": FakeVersion(),
        "context": "production",
        "cluster": "cluster-a",
        "default_namespace": "apps",
        "allowed_namespaces": allowed if allowed is not None else {"apps", "jobs"},
        "allowed_service_accounts": {"default", "deployer"},
    }
    return client.KubernetesService(connection, 20, 1024 * 1024), discovery


class MetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actions = {
            path.stem: path.read_text(encoding="utf-8")
            for path in sorted((ROOT / "actions").glob("*.yaml"))
        }

    def test_curated_inventory(self):
        self.assertEqual(ACTIONS, set(self.actions))
        self.assertEqual(31, len(self.actions))
        self.assertFalse((ROOT / "sensors").exists())

    def test_flat_json_contracts_and_no_inline_credentials(self):
        for name, text in self.actions.items():
            with self.subTest(action=name):
                for field, value in {
                    "ref": f"kubernetes.{name}",
                    "runner_type": "python",
                    "runtime_version": '">=3.10"',
                    "entry_point": "kubernetes_action.py",
                    "parameter_delivery": "stdin",
                    "parameter_format": "json",
                    "output_format": "json",
                }.items():
                    self.assertRegex(text, rf"(?m)^{field}: {re.escape(value)}$")
                self.assertIn("default_execution_permission_set_refs: [standard]", text)
                self.assertRegex(
                    text,
                    r"credential_key: \{[^\n]*default: pack\.kubernetes\.credentials[^\n]*\}",
                )
                for output in ("operation", "data", "meta"):
                    self.assertRegex(text, rf"(?m)^  {output}: \{{type:")
                self.assertNotRegex(
                    text, r"(?m)^  (token|kubeconfig|client_key|server):"
                )

    def test_no_legacy_or_unrestricted_surfaces(self):
        names = "\n".join(self.actions)
        for forbidden in (
            "exec",
            "proxy",
            "imperson",
            "third_party",
            "sensor",
            "generic_patch",
            "generic_delete",
            "generic_apply",
        ):
            self.assertNotIn(forbidden, names)
        source = (ROOT / "SOURCE.md").read_text(encoding="utf-8")
        self.assertIn("33 sensors", source)
        self.assertIn("367 generated action", source)
        self.assertIn("d6a52dbf72de7d3e034914299d3ac670d0532c38", source)

    def test_version_license_and_dependency_metadata(self):
        pack = (ROOT / "pack.yaml").read_text(encoding="utf-8")
        self.assertIn('source_version: "1.0.1"', pack)
        self.assertIn('client_version: "36.0.3"', pack)
        self.assertIn('license: "Apache-2.0"', pack)
        self.assertEqual(
            "kubernetes==36.0.3\nPyYAML==6.0.3\n",
            (ROOT / "requirements.txt").read_text(encoding="utf-8"),
        )
        self.assertIn("Apache License", (ROOT / "LICENSE").read_text(encoding="utf-8"))
        self.assertIn(
            "substantially changed", (ROOT / "NOTICE").read_text(encoding="utf-8")
        )


class CredentialTests(unittest.TestCase):
    def test_key_lookup_uses_current_sdk_signature(self):
        calls = {}
        get_key = types.ModuleType("attune.api_client.api.secrets.get_key")

        def sync_detailed(ref, *, client):
            calls.update(ref=ref, client=client)
            data = types.SimpleNamespace(value={"server": "https://api.example.invalid"})
            return types.SimpleNamespace(status_code=200, parsed=types.SimpleNamespace(data=data))

        get_key.sync_detailed = sync_detailed
        secrets = types.ModuleType("attune.api_client.api.secrets")
        secrets.get_key = get_key
        attune = types.ModuleType("attune")
        attune.context = types.SimpleNamespace(client="execution-client")
        modules = {
            "attune": attune,
            "attune.api_client": types.ModuleType("attune.api_client"),
            "attune.api_client.api": types.ModuleType("attune.api_client.api"),
            "attune.api_client.api.secrets": secrets,
        }
        with mock.patch.dict(sys.modules, modules):
            value = client._fetch_key("pack.kubernetes.credentials")
        self.assertEqual(value["server"], "https://api.example.invalid")
        self.assertEqual(calls, {"ref": "pack.kubernetes.credentials", "client": "execution-client"})

    def test_direct_credentials_require_https_identity_and_auth(self):
        valid = client._credential(
            {
                "server": "https://api.example.invalid:6443",
                "token": "TOKEN",
                "context": "prod",
                "cluster_name": "cluster-a",
                "default_namespace": "apps",
                "allowed_namespaces": ["apps"],
            }
        )
        self.assertEqual("prod", valid["context"])
        self.assertEqual({"apps"}, valid["allowed_namespaces"])
        bad = [
            {
                "server": "http://api.invalid",
                "token": "TOKEN",
                "context": "x",
                "cluster_name": "x",
            },
            {
                "server": "https://user:pass@api.invalid",
                "token": "TOKEN",
                "context": "x",
                "cluster_name": "x",
            },
            {
                "server": "https://api.invalid/path",
                "token": "TOKEN",
                "context": "x",
                "cluster_name": "x",
            },
            {"server": "https://api.invalid", "token": "TOKEN", "context": "x"},
            {"server": "https://api.invalid", "context": "x", "cluster_name": "x"},
            {
                "server": "https://api.invalid",
                "token": "TOKEN\nheader",
                "context": "x",
                "cluster_name": "x",
            },
            {
                "server": "https://api.invalid",
                "token": "TOKEN",
                "context": "x",
                "cluster_name": "x",
                "proxy": "https://proxy",
            },
        ]
        for settings in bad:
            with (
                self.subTest(settings=settings),
                self.assertRaises(client.KubernetesPackError),
            ):
                client._credential(settings)

    def test_kubeconfig_rejects_plugins_files_impersonation_and_insecure_tls(self):
        template = {
            "apiVersion": "v1",
            "kind": "Config",
            "current-context": "prod",
            "contexts": [
                {
                    "name": "prod",
                    "context": {
                        "cluster": "cluster-a",
                        "user": "worker",
                        "namespace": "apps",
                    },
                }
            ],
            "clusters": [
                {
                    "name": "cluster-a",
                    "cluster": {
                        "server": "https://api.invalid",
                        "certificate-authority-data": base64.b64encode(b"CA").decode(),
                    },
                }
            ],
            "users": [{"name": "worker", "user": {"token": "TOKEN"}}],
        }
        try:
            import yaml
        except ModuleNotFoundError:
            self.skipTest(
                "declared PyYAML dependency is not installed in this test runner"
            )
        parsed = client._parse_kubeconfig(yaml.safe_dump(template), "prod")
        self.assertEqual("cluster-a", parsed["cluster"])
        for section, field, value in (
            ("users", "exec", {"command": "steal"}),
            ("users", "tokenFile", "/tmp/token"),
            ("users", "as", "system:admin"),
            ("clusters", "insecure-skip-tls-verify", True),
            ("clusters", "proxy-url", "https://proxy.invalid"),
            ("clusters", "certificate-authority", "/tmp/ca"),
        ):
            modified = json.loads(json.dumps(template))
            key = "user" if section == "users" else "cluster"
            modified[section][0][key][field] = value
            with (
                self.subTest(field=field),
                self.assertRaises(client.KubernetesPackError),
            ):
                client._parse_kubeconfig(yaml.safe_dump(modified), "prod")
        for unsafe in (
            "a: &shared [1]\nb: *shared\n",
            "apiVersion: v1\napiVersion: v2\nkind: Config\n",
        ):
            with self.assertRaises(client.KubernetesPackError):
                client._parse_kubeconfig(unsafe, None)

    def test_key_references_are_pack_owned(self):
        with self.assertRaisesRegex(
            client.KubernetesPackError, "kubernetes pack namespace"
        ):
            client._fetch_key("other.credentials")

    def test_private_material_mode_and_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(client._write_private(directory, "client.key", b"PRIVATE"))
            self.assertEqual(0o600, path.stat().st_mode & 0o777)
        self.assertFalse(path.exists())

    def test_connection_bounds_discovery_disables_retries_and_cleans_material(self):
        try:
            import kubernetes.dynamic
            from kubernetes import client as kubernetes_client
        except ModuleNotFoundError:
            self.skipTest(
                "declared kubernetes dependency is not installed in this test runner"
            )

        instances = []

        class FakeApiClient:
            def __init__(self, configuration):
                self.configuration = configuration
                self.closed = False
                instances.append(self)

            def close(self):
                self.closed = True

        class FakeDynamicClient:
            def __init__(self, api_client):
                self.api_client = api_client
                self.calls = []

            def request(self, method, path, body=None, **params):
                self.calls.append((method, path, body, params))
                return {}

        settings = {
            "server": "https://api.example.invalid:6443",
            "token": "TOKEN",
            "context": "prod",
            "cluster_name": "cluster-a",
            "ca_cert": "CA",
            "client_cert": "CERT",
            "client_key": "PRIVATE",
        }
        with (
            mock.patch.object(kubernetes_client, "ApiClient", FakeApiClient),
            mock.patch.object(kubernetes_client, "CoreV1Api", lambda api: object()),
            mock.patch.object(kubernetes_client, "VersionApi", lambda api: object()),
            mock.patch.object(kubernetes.dynamic, "DynamicClient", FakeDynamicClient),
        ):
            with client._connection(settings, 17) as connection:
                configuration = instances[0].configuration
                paths = [
                    Path(configuration.ssl_ca_cert),
                    Path(configuration.cert_file),
                    Path(configuration.key_file),
                ]
                self.assertTrue(configuration.verify_ssl)
                self.assertTrue(configuration.assert_hostname)
                self.assertIsNone(configuration.proxy)
                self.assertEqual(0, configuration.retries)
                self.assertTrue(
                    all((path.stat().st_mode & 0o777) == 0o600 for path in paths)
                )
                connection["dynamic"].request("GET", "/apis")
                self.assertEqual(
                    (10, 17), connection["dynamic"].calls[0][3]["_request_timeout"]
                )
            self.assertTrue(instances[0].closed)
            self.assertTrue(all(not path.exists() for path in paths))


class OperationTests(unittest.TestCase):
    def test_paginated_list_passes_selectors_and_strips_managed_fields(self):
        svc, discovery = service()
        resource = discovery.add(
            FakeResource(
                "apps/v1",
                "Deployment",
                True,
                {
                    "metadata": {
                        "continue": "NEXT",
                        "resourceVersion": "50",
                        "remainingItemCount": 2,
                    },
                    "items": [
                        {
                            "metadata": {
                                "name": "web",
                                "namespace": "apps",
                                "managedFields": ["x"],
                            }
                        }
                    ],
                },
            )
        )
        result = svc.dispatch(
            "workload_list",
            {
                "kind": "Deployment",
                "namespace": "apps",
                "limit": 25,
                "continue_token": "TOKEN",
                "label_selector": "app=web",
            },
        )
        self.assertEqual("NEXT", result["data"]["continue_token"])
        self.assertEqual("50", result["data"]["resource_version"])
        self.assertNotIn("managedFields", result["data"]["items"][0]["metadata"])
        kwargs = resource.calls[0][1]
        self.assertEqual(25, kwargs["limit"])
        self.assertEqual("TOKEN", kwargs["_continue"])
        self.assertEqual((10, 20), kwargs["_request_timeout"])

    def test_namespace_policy_prevents_cross_namespace_requests(self):
        svc, discovery = service({"apps"})
        discovery.add(FakeResource("v1", "Pod", True))
        with self.assertRaisesRegex(client.KubernetesPackError, "outside"):
            svc.dispatch("pod_get", {"namespace": "kube-system", "name": "api"})
        self.assertEqual([], discovery.calls)

    def test_server_side_apply_identity_ownership_dry_run_and_policy(self):
        svc, discovery = service()
        resource = discovery.add(FakeResource("apps/v1", "Deployment", True))
        body = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "web", "namespace": "apps"},
            "spec": {
                "template": {
                    "spec": {
                        "serviceAccountName": "deployer",
                        "containers": [{"name": "web", "image": "example/web:1"}],
                    }
                }
            },
        }
        result = svc.dispatch(
            "workload_apply",
            {
                "kind": "Deployment",
                "namespace": "apps",
                "name": "web",
                "body": body,
                "dry_run": True,
            },
        )
        call = resource.calls[0]
        self.assertEqual("server_side_apply", call[0])
        self.assertEqual("attune-kubernetes", call[1]["field_manager"])
        self.assertFalse(call[1]["force_conflicts"])
        self.assertEqual("All", call[1]["dry_run"])
        self.assertTrue(result["meta"]["dry_run"])
        privileged = json.loads(json.dumps(body))
        privileged["spec"]["template"]["spec"]["containers"][0]["securityContext"] = {
            "privileged": True
        }
        with self.assertRaisesRegex(client.KubernetesPackError, "privileged"):
            svc.dispatch(
                "workload_apply",
                {"kind": "Deployment", "name": "web", "body": privileged},
            )
        host_process = json.loads(json.dumps(body))
        host_process["spec"]["template"]["spec"]["containers"][0]["securityContext"] = {
            "windowsOptions": {"hostProcess": True}
        }
        with self.assertRaisesRegex(client.KubernetesPackError, "HostProcess"):
            svc.dispatch(
                "workload_apply",
                {"kind": "Deployment", "name": "web", "body": host_process},
            )

    def test_patch_resource_version_and_unsafe_objects(self):
        svc, discovery = service()
        resource = discovery.add(FakeResource("v1", "ConfigMap", True))
        svc.dispatch(
            "core_patch",
            {
                "kind": "ConfigMap",
                "name": "settings",
                "patch": {"data": {"mode": "safe"}},
                "resource_version": "18",
            },
        )
        body = resource.calls[0][1]["body"]
        self.assertEqual("18", body["metadata"]["resourceVersion"])
        self.assertEqual(
            "application/merge-patch+json", resource.calls[0][1]["content_type"]
        )
        with self.assertRaisesRegex(client.KubernetesPackError, "JSON values"):
            client._json_object({"bad": object()}, "body")

    def test_scale_and_deletion_guards(self):
        svc, discovery = service()
        deployment = discovery.add(FakeResource("apps/v1", "Deployment", True))
        result = svc.dispatch(
            "workload_scale",
            {
                "kind": "Deployment",
                "name": "web",
                "replicas": 3,
                "resource_version": "20",
            },
        )
        self.assertEqual(3, result["data"]["replicas"])
        self.assertEqual(
            "20", deployment.scale.calls[0][1]["body"]["metadata"]["resourceVersion"]
        )
        with self.assertRaisesRegex(client.KubernetesPackError, "no scale"):
            svc.dispatch(
                "workload_scale", {"kind": "DaemonSet", "name": "agent", "replicas": 2}
            )
        with self.assertRaisesRegex(client.KubernetesPackError, "confirm"):
            svc.dispatch(
                "workload_delete",
                {"kind": "Deployment", "name": "web", "confirm": "wrong"},
            )
        result = svc.dispatch(
            "workload_delete",
            {
                "kind": "Deployment",
                "name": "web",
                "confirm": "apps/web",
                "propagation_policy": "Foreground",
                "resource_version": "20",
            },
        )
        delete = deployment.calls[-1][1]
        self.assertEqual("Foreground", delete["body"]["propagationPolicy"])
        self.assertEqual("20", delete["body"]["preconditions"]["resourceVersion"])
        self.assertTrue(result["data"]["accepted"])

    @mock.patch.object(client, "_fetch_key")
    def test_secret_update_uses_key_and_never_returns_data(self, fetch_key):
        fetch_key.return_value = {
            "string_data": {"password": "DO-NOT-RETURN"},
            "data": {"tls.key": base64.b64encode(b"PRIVATE").decode()},
        }
        svc, discovery = service()
        resource = discovery.add(
            FakeResource(
                "v1",
                "Secret",
                True,
                {
                    "metadata": {
                        "name": "login",
                        "namespace": "apps",
                        "resourceVersion": "31",
                    },
                    "data": {"password": "DO-NOT-RETURN"},
                    "stringData": {"password": "DO-NOT-RETURN"},
                },
            )
        )
        result = svc.dispatch(
            "secret_write",
            {
                "name": "login",
                "secret_key": "pack.kubernetes.secret_login",
                "mode": "update",
                "resource_version": "30",
                "confirm": "apps/login",
            },
        )
        encoded = json.dumps(result)
        self.assertNotIn("DO-NOT-RETURN", encoded)
        self.assertNotIn('"data"', json.dumps(result["data"]["resource"]))
        self.assertEqual(
            "30", resource.calls[0][1]["body"]["metadata"]["resourceVersion"]
        )
        with self.assertRaisesRegex(client.KubernetesPackError, "resource_version"):
            svc.dispatch(
                "secret_write",
                {
                    "name": "login",
                    "secret_key": "x",
                    "mode": "update",
                    "confirm": "apps/login",
                },
            )

    def test_generic_allowlist_is_exact_and_discovery_checked(self):
        svc, discovery = service()
        discovery.add(FakeResource("networking.k8s.io/v1", "Ingress", True))
        result = svc.dispatch(
            "generic_get",
            {
                "api_version": "networking.k8s.io/v1",
                "kind": "Ingress",
                "name": "public",
            },
        )
        self.assertEqual("Ingress", result["meta"]["kind"])
        with self.assertRaisesRegex(client.KubernetesPackError, "allowlist"):
            svc.dispatch(
                "generic_get", {"api_version": "v1", "kind": "Secret", "name": "login"}
            )
        self.assertNotIn(("v1", "Secret"), discovery.calls)
        wrong_scope = FakeResource("policy/v1", "PodDisruptionBudget", False)
        discovery.add(wrong_scope)
        with self.assertRaisesRegex(client.KubernetesPackError, "scope"):
            svc.dispatch(
                "generic_get",
                {
                    "api_version": "policy/v1",
                    "kind": "PodDisruptionBudget",
                    "name": "web",
                },
            )

    def test_pod_logs_are_non_following_and_bounded(self):
        svc, _ = service()
        result = svc.dispatch(
            "pod_logs",
            {
                "name": "web-1",
                "container": "web",
                "tail_lines": 20,
                "max_log_bytes": 1024,
            },
        )
        kwargs = svc.connection["core"].calls[0]
        self.assertNotIn("follow", kwargs)
        self.assertEqual(1024, kwargs["limit_bytes"])
        self.assertEqual(20, kwargs["tail_lines"])
        self.assertIn("line one", result["data"]["logs"])

    def test_completed_rollout_does_not_open_watch(self):
        svc, discovery = service()
        discovery.add(
            FakeResource(
                "apps/v1",
                "Deployment",
                True,
                {
                    "metadata": {
                        "name": "web",
                        "namespace": "apps",
                        "generation": 2,
                        "resourceVersion": "40",
                    },
                    "spec": {"replicas": 2},
                    "status": {
                        "observedGeneration": 2,
                        "updatedReplicas": 2,
                        "availableReplicas": 2,
                        "unavailableReplicas": 0,
                    },
                },
            )
        )
        result = svc.dispatch(
            "rollout_status",
            {"kind": "Deployment", "name": "web", "watch_timeout_seconds": 60},
        )
        self.assertTrue(result["data"]["complete"])
        self.assertEqual(60, result["meta"]["watch_timeout_seconds"])

    def test_api_errors_redact_body_reason_and_credentials(self):
        class ApiError(Exception):
            status = 403

        def fail():
            raise ApiError("TOKEN DO-NOT-RETURN response body")

        with self.assertRaises(client.KubernetesPackError) as caught:
            client._call(fail)
        message = str(caught.exception)
        self.assertEqual("Kubernetes API request failed (HTTP 403 forbidden)", message)
        self.assertNotIn("TOKEN", message)


class EntryPointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "kubernetes_action_test", ROOT / "actions" / "kubernetes_action.py"
        )
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_invalid_input_and_unknown_errors_do_not_echo_secrets(self):
        cases = [
            ("[]", None),
            ('{"secret_key":"DO-NOT-ECHO"}', RuntimeError("DO-NOT-ECHO")),
        ]
        for raw, error in cases:
            stdout, stderr = io.StringIO(), io.StringIO()
            patch_execute = (
                mock.patch.object(self.module, "execute_action", side_effect=error)
                if error
                else mock.patch.object(self.module, "execute_action")
            )
            with (
                patch_execute,
                mock.patch.dict(
                    os.environ, {"ATTUNE_ACTION": "kubernetes.secret_write"}
                ),
                mock.patch("sys.stdin", io.StringIO(raw)),
                mock.patch("sys.stdout", stdout),
                mock.patch("sys.stderr", stderr),
            ):
                self.assertEqual(1, self.module.main())
            self.assertEqual("", stdout.getvalue())
            self.assertNotIn("DO-NOT-ECHO", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
