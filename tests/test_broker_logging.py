import importlib.util
import logging
from pathlib import Path
import sys
import types
import unittest

from requests import Response


pyotp_module = types.ModuleType("pyotp")


class _DummyTOTP:
    def __init__(self, *args, **kwargs):
        pass


pyotp_module.TOTP = _DummyTOTP
sys.modules.setdefault("pyotp", pyotp_module)


ROOT_DIR = Path(__file__).resolve().parents[1]
FENIX_DIR = ROOT_DIR / "fenix"
BASE_DIR = FENIX_DIR / "base"


def _load_module(module_name: str, file_path: Path):
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


fenix_package = types.ModuleType("fenix")
fenix_package.__path__ = [str(FENIX_DIR)]
sys.modules.setdefault("fenix", fenix_package)

fenix_base_package = types.ModuleType("fenix.base")
fenix_base_package.__path__ = [str(BASE_DIR)]
sys.modules.setdefault("fenix.base", fenix_base_package)

constants_module = _load_module("fenix.base.constants", BASE_DIR / "constants.py")
errors_module = _load_module("fenix.base.errors", BASE_DIR / "errors.py")
broker_module = _load_module("fenix.base.broker", BASE_DIR / "broker.py")

fenix_package.base = fenix_base_package
fenix_base_package.constants = constants_module
fenix_base_package.errors = errors_module
fenix_base_package.broker = broker_module

Broker = broker_module.Broker


class _FakeSession:
    def __init__(self, response: Response):
        self.headers = {"User-Agent": "fake-session"}
        self.calls = []
        self.response = response

    def request(self, **kwargs):
        self.calls.append(kwargs)
        return self.response


class _LoggingBroker(Broker):
    def describe(self):
        return {
            "id": "logtest",
            "enableRateLimit": False,
        }


def _response(body: str, url: str) -> Response:
    response = Response()
    response.status_code = 200
    response.reason = "OK"
    response.url = url
    response.headers = {
        "Content-Type": "application/json",
        "Set-Cookie": "server-cookie",
    }
    response._content = body.encode("utf-8")
    return response


class BrokerLoggingTests(unittest.TestCase):
    def test_fetch_logs_redacted_http_trace_and_keeps_raw_snapshots(self):
        logger = logging.getLogger("fenix.tests.broker_logging")
        broker = _LoggingBroker({
            "logger": logger,
            "enableLastJsonResponse": True,
        })
        broker.headers = {"X-Api-Key": "global-secret"}
        broker._headers = {"Authorization": "Bearer legacy-secret"}
        broker._session = _FakeSession(_response(
            '{"ok": true, "access_token": "server-secret"}',
            "https://broker.example/orders?access_token=server-secret",
        ))

        with self.assertLogs(logger, level="DEBUG") as captured:
            result = broker.fetch(
                method="POST",
                url="https://broker.example/orders?access_token=query-secret",
                endpoint_group="orders",
                headers={"Authorization": "Bearer call-secret"},
                json={"password": "request-secret", "quantity": 1},
                params={"api_key": "param-secret", "symbol": "SBIN"},
            )

        self.assertIs(result, broker._session.response)
        sent_headers = broker._session.calls[0]["headers"]
        self.assertEqual(sent_headers["Authorization"], "Bearer call-secret")
        self.assertEqual(sent_headers["X-Api-Key"], "global-secret")
        self.assertEqual(broker.last_request_headers["Authorization"], "Bearer call-secret")
        self.assertEqual(broker.last_request_body["password"], "request-secret")
        self.assertEqual(
            broker.last_json_response,
            {"ok": True, "access_token": "server-secret"},
        )
        self.assertEqual(
            broker.last_http_response,
            '{"ok": true, "access_token": "server-secret"}',
        )
        self.assertEqual(broker.last_response_headers["Content-Type"], "application/json")

        logs = "\n".join(captured.output)
        self.assertIn("***", logs)
        self.assertIn("symbol", logs)
        for secret in [
            "global-secret",
            "legacy-secret",
            "call-secret",
            "request-secret",
            "param-secret",
            "query-secret",
            "server-secret",
            "server-cookie",
        ]:
            self.assertNotIn(secret, logs)

    def test_log_sensitive_opt_in_keeps_values_visible(self):
        logger = logging.getLogger("fenix.tests.broker_logging.sensitive")
        broker = _LoggingBroker({
            "logger": logger,
            "logSensitive": True,
        })
        broker._session = _FakeSession(_response(
            '{"ok": true}',
            "https://broker.example/orders",
        ))

        with self.assertLogs(logger, level="DEBUG") as captured:
            broker.fetch(
                method="GET",
                url="https://broker.example/orders?api_key=query-secret",
                endpoint_group="orders",
                headers={"Authorization": "Bearer call-secret"},
            )

        logs = "\n".join(captured.output)
        self.assertIn("query-secret", logs)
        self.assertIn("Bearer call-secret", logs)

    def test_broker_specific_sensitive_log_keys_are_redacted(self):
        logger = logging.getLogger("fenix.tests.broker_logging.custom_keys")
        broker = _LoggingBroker({
            "logger": logger,
            "sensitiveLogKeys": ["X-Broker-Session", "clientSecret"],
        })
        broker._session = _FakeSession(_response(
            '{"ok": true, "clientSecret": "response-secret"}',
            "https://broker.example/orders?clientSecret=query-secret",
        ))

        with self.assertLogs(logger, level="DEBUG") as captured:
            broker.fetch(
                method="POST",
                url="https://broker.example/orders?clientSecret=query-secret",
                endpoint_group="orders",
                headers={"X-Broker-Session": "header-secret"},
                json={"clientSecret": "body-secret", "symbol": "SBIN"},
            )

        logs = "\n".join(captured.output)
        self.assertIn("***", logs)
        self.assertIn("symbol", logs)
        self.assertNotIn("query-secret", logs)
        self.assertNotIn("header-secret", logs)
        self.assertNotIn("body-secret", logs)
        self.assertNotIn("response-secret", logs)

    def test_sensitive_log_keys_can_replace_defaults(self):
        logger = logging.getLogger("fenix.tests.broker_logging.custom_only")
        broker = _LoggingBroker({
            "logger": logger,
            "sensitiveLogKeysIncludeDefault": False,
            "sensitiveLogKeys": ["brokerToken"],
        })
        broker._session = _FakeSession(_response(
            '{"brokerToken": "response-secret", "access_token": "visible-token"}',
            "https://broker.example/orders?brokerToken=query-secret",
        ))

        with self.assertLogs(logger, level="DEBUG") as captured:
            broker.fetch(
                method="GET",
                url="https://broker.example/orders?brokerToken=query-secret&access_token=visible-token",
                endpoint_group="orders",
            )

        logs = "\n".join(captured.output)
        self.assertNotIn("query-secret", logs)
        self.assertNotIn("response-secret", logs)
        self.assertIn("visible-token", logs)

    def test_on_json_response_accepts_response_or_text(self):
        response = _response('{"ok": true}', "https://broker.example/orders")

        self.assertEqual(Broker.on_json_response(response), {"ok": True})
        self.assertEqual(Broker.on_json_response(response.text), {"ok": True})


if __name__ == "__main__":
    unittest.main()
