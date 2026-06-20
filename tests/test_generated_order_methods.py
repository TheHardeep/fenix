"""
Tests for the dynamically generated convenience order methods on
:class:`fenix.base.broker.Broker`.

Every variant defined in ``_ORDER_VARIANTS`` is exercised against a mocked
``create_order`` to verify:

  * the correct side, price, trigger, and variety are forwarded;
  * ``NotSupported`` is raised when ``self.has[<method>]`` is ``False``;
  * subclass ``has`` dicts merge with the parent's instead of replacing it.
"""

import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock

# ── Stub optional runtime dependencies so broker.py imports cleanly ──────────
pyotp_module = types.ModuleType("pyotp")


class _DummyTOTP:
    def __init__(self, *args, **kwargs):
        pass


pyotp_module.TOTP = _DummyTOTP
sys.modules.setdefault("pyotp", pyotp_module)

# ── Load the fenix package from source without triggering broker imports ────
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
_ORDER_VARIANTS = broker_module._ORDER_VARIANTS
NotSupported = errors_module.NotSupported
Side = constants_module.Side
Variety = constants_module.Variety


# ── Minimal concrete subclass that records every call to ``create_order`` ───
class _FakeBroker(Broker):
    """Concrete Broker that captures ``create_order`` calls."""

    def __init__(self):
        # Intentionally do not call super().__init__() — we don't need the
        # session, rate limiter, or describe() machinery for these tests.
        self.create_order = MagicMock(return_value={"id": "mocked"})


# ── Per-variant expectations used across several test methods ──────────────
def _call_args_for(variant) -> dict:
    """
    Build the minimum set of kwargs needed to call ``variant.name`` on a
    broker, plus a sentinel value for every parameter the variant does
    *not* bake in so we can assert it gets forwarded verbatim.
    """
    kwargs = {
        "token_dict": {"symbol": "TCS"},
        "quantity": 10,
        "unique_id": "test-001",
    }
    if variant.side is None:
        kwargs["side"] = Side.BUY
    if variant.price is None:
        kwargs["price"] = 123.45
    if variant.trigger is None:
        kwargs["trigger"] = 120.00
    return kwargs


def _expected_side(variant, call_kwargs):
    return variant.side if variant.side is not None else call_kwargs["side"]


def _expected_price(variant, call_kwargs):
    return variant.price if variant.price is not None else call_kwargs["price"]


def _expected_trigger(variant, call_kwargs):
    return variant.trigger if variant.trigger is not None else call_kwargs["trigger"]


class GeneratedOrderMethodsTests(unittest.TestCase):
    """Verify each generated method forwards the right values."""

    def test_all_variants_are_installed_on_broker(self):
        for variant in _ORDER_VARIANTS:
            with self.subTest(variant=variant.name):
                method = getattr(Broker, variant.name, None)
                self.assertIsNotNone(method, f"missing method: {variant.name}")
                self.assertTrue(callable(method))
                self.assertEqual(method.__name__, variant.name)
                self.assertEqual(method.__qualname__, f"Broker.{variant.name}")

    def test_each_variant_forwards_expected_side_price_trigger_variety(self):
        for variant in _ORDER_VARIANTS:
            with self.subTest(variant=variant.name):
                broker = _FakeBroker()
                kwargs = _call_args_for(variant)
                getattr(broker, variant.name)(**kwargs)

                broker.create_order.assert_called_once()
                _, forwarded = broker.create_order.call_args

                self.assertEqual(forwarded["side"], _expected_side(variant, kwargs))
                self.assertEqual(forwarded["price"], _expected_price(variant, kwargs))
                self.assertEqual(forwarded["trigger"], _expected_trigger(variant, kwargs))
                self.assertEqual(forwarded["variety"], variant.variety)
                self.assertEqual(forwarded["quantity"], 10)
                self.assertEqual(forwarded["unique_id"], "test-001")

    def test_raises_not_supported_when_capability_is_disabled(self):
        for variant in _ORDER_VARIANTS:
            with self.subTest(variant=variant.name):

                class _DisabledBroker(Broker):
                    has = {variant.name: False}

                    def __init__(self):
                        self.create_order = MagicMock()

                broker = _DisabledBroker()
                kwargs = _call_args_for(variant)

                with self.assertRaises(NotSupported):
                    getattr(broker, variant.name)(**kwargs)
                broker.create_order.assert_not_called()


class CapabilityRegistryTests(unittest.TestCase):
    """Verify the ``has`` registry and its inheritance behaviour."""

    def test_base_broker_advertises_every_variant_as_true(self):
        self.assertTrue(Broker.has["create_order"])
        for variant in _ORDER_VARIANTS:
            with self.subTest(variant=variant.name):
                self.assertTrue(Broker.has[variant.name])

    def test_subclass_has_dict_merges_with_parent(self):
        class _PartiallyDisabled(Broker):
            has = {"slm_buy_order": False, "slm_sell_order": False}

        # Overridden keys are false; everything else remains true.
        self.assertFalse(_PartiallyDisabled.has["slm_buy_order"])
        self.assertFalse(_PartiallyDisabled.has["slm_sell_order"])
        self.assertTrue(_PartiallyDisabled.has["market_buy_order"])
        self.assertTrue(_PartiallyDisabled.has["create_order"])

        # Parent's dict is not mutated.
        self.assertTrue(Broker.has["slm_buy_order"])

    def test_subclass_without_has_inherits_parent_dict(self):
        class _Unchanged(Broker):
            pass

        self.assertEqual(_Unchanged.has, Broker.has)
        # ...but is a separate dict, so future mutations do not cross over.
        self.assertIsNot(_Unchanged.has, Broker.has)

    def test_new_keys_introduced_by_subclass_are_preserved(self):
        class _ExtraCapability(Broker):
            has = {"create_gtt_order": True}

        self.assertTrue(_ExtraCapability.has["create_gtt_order"])
        self.assertTrue(_ExtraCapability.has["market_buy_order"])

    def test_grandchild_sees_merged_chain(self):
        class _Parent(Broker):
            has = {"limit_buy_order": False}

        class _Child(_Parent):
            has = {"limit_sell_order": False}

        self.assertFalse(_Child.has["limit_buy_order"])
        self.assertFalse(_Child.has["limit_sell_order"])
        self.assertTrue(_Child.has["market_buy_order"])


if __name__ == "__main__":
    unittest.main()
