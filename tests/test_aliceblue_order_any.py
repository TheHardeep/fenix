import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

pyotp_module = types.ModuleType("pyotp")


class _DummyTOTP:
    def __init__(self, *args, **kwargs):
        pass


pyotp_module.TOTP = _DummyTOTP
sys.modules.setdefault("pyotp", pyotp_module)

cryptography_module = types.ModuleType("cryptography")
hazmat_module = types.ModuleType("cryptography.hazmat")
primitives_module = types.ModuleType("cryptography.hazmat.primitives")
ciphers_module = types.ModuleType("cryptography.hazmat.primitives.ciphers")
algorithms_module = types.ModuleType(
    "cryptography.hazmat.primitives.ciphers.algorithms"
)
modes_module = types.ModuleType("cryptography.hazmat.primitives.ciphers.modes")


class _DummyCipher:
    def __init__(self, *args, **kwargs):
        pass


class _DummyAlgorithm:
    def __init__(self, *args, **kwargs):
        pass


class _DummyMode:
    def __init__(self, *args, **kwargs):
        pass


ciphers_module.Cipher = _DummyCipher
algorithms_module.AES = _DummyAlgorithm
modes_module.CBC = _DummyMode
ciphers_module.algorithms = algorithms_module
ciphers_module.modes = modes_module
primitives_module.ciphers = ciphers_module
hazmat_module.primitives = primitives_module
cryptography_module.hazmat = hazmat_module

sys.modules.setdefault("cryptography", cryptography_module)
sys.modules.setdefault("cryptography.hazmat", hazmat_module)
sys.modules.setdefault("cryptography.hazmat.primitives", primitives_module)
sys.modules.setdefault("cryptography.hazmat.primitives.ciphers", ciphers_module)
sys.modules.setdefault(
    "cryptography.hazmat.primitives.ciphers.algorithms",
    algorithms_module,
)
sys.modules.setdefault(
    "cryptography.hazmat.primitives.ciphers.modes",
    modes_module,
)

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
aliceblue_module = _load_module("fenix.aliceblue", FENIX_DIR / "aliceblue.py")

fenix_package.base = fenix_base_package
fenix_base_package.constants = constants_module
fenix_base_package.errors = errors_module
fenix_base_package.broker = broker_module
fenix_package.aliceblue = aliceblue_module

AliceBlue = aliceblue_module.AliceBlue
Broker = broker_module.Broker
InputError = errors_module.InputError
OrderType = constants_module.OrderType
Product = constants_module.Product
Side = constants_module.Side
Validity = constants_module.Validity
Variety = constants_module.Variety


class AliceBlueOrderAnyTests(unittest.TestCase):
    def setUp(self):
        self.broker = AliceBlue()
        self.broker.headers = {"Authorization": "Bearer test"}
        self.token_dict = {
            "Token": 12345,
            "Exchange": "NSE",
            "Symbol": "SBIN-EQ",
        }

    def test_order_type_resolution_truth_table(self):
        cases = [
            ((0.0, 10.0), OrderType.SLM),
            ((0.0, 0.0), OrderType.MARKET),
            ((10.0, 0.0), OrderType.LIMIT),
            ((10.0, 5.0), OrderType.SL),
        ]

        for (price, trigger), expected in cases:
            with self.subTest(price=price, trigger=trigger):
                self.assertEqual(
                    self.broker._resolve_order_type_from_any(price, trigger),
                    expected,
                )

    def test_any_helpers_are_inherited_from_broker(self):
        self.assertIs(AliceBlue.market_order_any, Broker.market_order_any)
        self.assertIs(AliceBlue.limit_order_any, Broker.limit_order_any)
        self.assertIs(AliceBlue.sl_order_any, Broker.sl_order_any)
        self.assertIs(AliceBlue.slm_order_any, Broker.slm_order_any)

    def test_any_helpers_delegate_to_create_order_any(self):
        cases = [
            (
                "market_order_any",
                {
                    "token_dict": self.token_dict,
                    "quantity": 2,
                    "side": Side.BUY,
                    "unique_id": "market-1",
                },
                {
                    "token_dict": self.token_dict,
                    "quantity": 2,
                    "side": Side.BUY,
                    "product": Product.MIS,
                    "validity": Validity.DAY,
                    "variety": Variety.REGULAR,
                    "unique_id": "market-1",
                    "price": 0.0,
                    "trigger": 0.0,
                    "target": 0.0,
                    "stoploss": 0.0,
                    "trailing_sl": 0.0,
                },
            ),
            (
                "limit_order_any",
                {
                    "token_dict": self.token_dict,
                    "price": 100.5,
                    "quantity": 2,
                    "side": Side.BUY,
                    "unique_id": "limit-1",
                },
                {
                    "token_dict": self.token_dict,
                    "quantity": 2,
                    "side": Side.BUY,
                    "product": Product.MIS,
                    "validity": Validity.DAY,
                    "variety": Variety.REGULAR,
                    "unique_id": "limit-1",
                    "price": 100.5,
                    "trigger": 0.0,
                    "target": 0.0,
                    "stoploss": 0.0,
                    "trailing_sl": 0.0,
                },
            ),
            (
                "sl_order_any",
                {
                    "token_dict": self.token_dict,
                    "price": 101.0,
                    "trigger": 100.0,
                    "quantity": 2,
                    "side": Side.SELL,
                    "unique_id": "sl-1",
                },
                {
                    "token_dict": self.token_dict,
                    "quantity": 2,
                    "side": Side.SELL,
                    "product": Product.MIS,
                    "validity": Validity.DAY,
                    "variety": Variety.STOPLOSS,
                    "unique_id": "sl-1",
                    "price": 101.0,
                    "trigger": 100.0,
                    "target": 0.0,
                    "stoploss": 0.0,
                    "trailing_sl": 0.0,
                },
            ),
            (
                "slm_order_any",
                {
                    "token_dict": self.token_dict,
                    "trigger": 99.0,
                    "quantity": 2,
                    "side": Side.SELL,
                    "unique_id": "slm-1",
                },
                {
                    "token_dict": self.token_dict,
                    "quantity": 2,
                    "side": Side.SELL,
                    "product": Product.MIS,
                    "validity": Validity.DAY,
                    "variety": Variety.STOPLOSS,
                    "unique_id": "slm-1",
                    "price": 0.0,
                    "trigger": 99.0,
                    "target": 0.0,
                    "stoploss": 0.0,
                    "trailing_sl": 0.0,
                },
            ),
        ]

        for method_name, call_kwargs, expected_kwargs in cases:
            with self.subTest(method=method_name):
                expected_result = {"id": method_name}
                with patch.object(
                    self.broker,
                    "create_order_any",
                    return_value=expected_result,
                ) as mocked:
                    result = getattr(self.broker, method_name)(**call_kwargs)

                self.assertEqual(result, expected_result)
                mocked.assert_called_once_with(**expected_kwargs)

    def test_non_bracket_payload_shape(self):
        payload = self.broker._build_order_any_payload(
            token_dict=self.token_dict,
            quantity=2,
            side=Side.BUY,
            product=Product.MIS,
            validity=Validity.DAY,
            variety=Variety.REGULAR,
            unique_id="abc-123",
            price=101.5,
            trigger=0.0,
        )[0]

        self.assertEqual(
            payload,
            {
                "instrumentId": 12345,
                "exchange": "NSE",
                "trading_symbol": "SBIN-EQ",
                "price": 101.5,
                "slTriggerPrice": 0.0,
                "quantity": 2,
                "transactionType": "BUY",
                "orderType": "LIMIT",
                "product": "INTRADAY",
                "validity": "DAY",
                "orderComplexity": "REGULAR",
                "orderTag": "abc-123",
                "disclosedQuantity": 0,
                "apiOrderSource": "MyAlgomate",
            },
        )
        self.assertNotIn("targetLegPrice", payload)
        self.assertNotIn("slLegPrice", payload)
        self.assertNotIn("trailingSlAmount", payload)

    def test_bracket_payload_shape_forces_bo(self):
        payload = self.broker._build_order_any_payload(
            token_dict=self.token_dict,
            quantity=2,
            side=Side.SELL,
            product=Product.MIS,
            validity=Validity.DAY,
            variety=Variety.STOPLOSS,
            unique_id="abc-456",
            price=0.0,
            trigger=99.0,
            target=10.0,
            stoploss=5.0,
            trailing_sl=2.0,
        )[0]

        self.assertEqual(payload["orderType"], "SLM")
        self.assertEqual(payload["orderComplexity"], "BO")
        self.assertEqual(payload["targetLegPrice"], 10.0)
        self.assertEqual(payload["slLegPrice"], 5.0)
        self.assertEqual(payload["trailingSlAmount"], 2.0)

    def test_create_order_any_returns_parser_result_and_sends_payload(self):
        parsed = {"order_id": "broker-1"}
        response = object()
        with patch.object(self.broker, "fetch", return_value=response) as fetch_mock:
            with patch.object(
                self.broker,
                "_create_order_parser",
                return_value=parsed,
            ) as parser_mock:
                result = self.broker.create_order_any(
                    token_dict=self.token_dict,
                    quantity=3,
                    side=Side.BUY,
                    product=Product.MIS,
                    validity=Validity.DAY,
                    variety=Variety.REGULAR,
                    unique_id="create-1",
                    price=100.0,
                    trigger=0.0,
                )

        self.assertEqual(result, parsed)
        parser_mock.assert_called_once_with(response=response)
        self.assertEqual(
            fetch_mock.call_args.kwargs["json"],
            [
                {
                    "instrumentId": 12345,
                    "exchange": "NSE",
                    "trading_symbol": "SBIN-EQ",
                    "price": 100.0,
                    "slTriggerPrice": 0.0,
                    "quantity": 3,
                    "transactionType": "BUY",
                    "orderType": "LIMIT",
                    "product": "INTRADAY",
                    "validity": "DAY",
                    "orderComplexity": "REGULAR",
                    "orderTag": "create-1",
                    "disclosedQuantity": 0,
                    "apiOrderSource": "MyAlgomate",
                }
            ],
        )

    def test_helper_payload_regression(self):
        cases = [
            (
                "market_order_any",
                {
                    "token_dict": self.token_dict,
                    "quantity": 2,
                    "side": Side.BUY,
                    "unique_id": "market-1",
                },
                {
                    "instrumentId": 12345,
                    "exchange": "NSE",
                    "trading_symbol": "SBIN-EQ",
                    "price": 0.0,
                    "slTriggerPrice": 0.0,
                    "quantity": 2,
                    "transactionType": "BUY",
                    "orderType": "MARKET",
                    "product": "INTRADAY",
                    "validity": "DAY",
                    "orderComplexity": "REGULAR",
                    "orderTag": "market-1",
                    "disclosedQuantity": 0,
                    "apiOrderSource": "MyAlgomate",
                },
            ),
            (
                "limit_order_any",
                {
                    "token_dict": self.token_dict,
                    "price": 101.5,
                    "quantity": 2,
                    "side": Side.BUY,
                    "unique_id": "limit-1",
                },
                {
                    "instrumentId": 12345,
                    "exchange": "NSE",
                    "trading_symbol": "SBIN-EQ",
                    "price": 101.5,
                    "slTriggerPrice": 0.0,
                    "quantity": 2,
                    "transactionType": "BUY",
                    "orderType": "LIMIT",
                    "product": "INTRADAY",
                    "validity": "DAY",
                    "orderComplexity": "REGULAR",
                    "orderTag": "limit-1",
                    "disclosedQuantity": 0,
                    "apiOrderSource": "MyAlgomate",
                },
            ),
            (
                "sl_order_any",
                {
                    "token_dict": self.token_dict,
                    "price": 101.0,
                    "trigger": 100.0,
                    "quantity": 2,
                    "side": Side.SELL,
                    "unique_id": "sl-1",
                },
                {
                    "instrumentId": 12345,
                    "exchange": "NSE",
                    "trading_symbol": "SBIN-EQ",
                    "price": 101.0,
                    "slTriggerPrice": 100.0,
                    "quantity": 2,
                    "transactionType": "SELL",
                    "orderType": "SL",
                    "product": "INTRADAY",
                    "validity": "DAY",
                    "orderComplexity": "REGULAR",
                    "orderTag": "sl-1",
                    "disclosedQuantity": 0,
                    "apiOrderSource": "MyAlgomate",
                },
            ),
            (
                "slm_order_any",
                {
                    "token_dict": self.token_dict,
                    "trigger": 99.0,
                    "quantity": 2,
                    "side": Side.SELL,
                    "unique_id": "slm-1",
                },
                {
                    "instrumentId": 12345,
                    "exchange": "NSE",
                    "trading_symbol": "SBIN-EQ",
                    "price": 0.0,
                    "slTriggerPrice": 99.0,
                    "quantity": 2,
                    "transactionType": "SELL",
                    "orderType": "SLM",
                    "product": "INTRADAY",
                    "validity": "DAY",
                    "orderComplexity": "REGULAR",
                    "orderTag": "slm-1",
                    "disclosedQuantity": 0,
                    "apiOrderSource": "MyAlgomate",
                },
            ),
        ]

        for method_name, call_kwargs, expected_payload in cases:
            with self.subTest(method=method_name):
                with patch.object(self.broker, "fetch", return_value=object()) as fetch_mock:
                    with patch.object(
                        self.broker,
                        "_create_order_parser",
                        return_value={"ok": True},
                    ):
                        result = getattr(self.broker, method_name)(**call_kwargs)

                self.assertEqual(result, {"ok": True})
                self.assertEqual(fetch_mock.call_args.kwargs["json"], [expected_payload])

    def test_create_order_any_rejects_invalid_negative_values(self):
        cases = [
            {"quantity": 0},
            {"price": -1.0},
            {"trigger": -1.0},
            {"target": -1.0},
            {"stoploss": -1.0},
            {"trailing_sl": -1.0},
        ]

        for overrides in cases:
            with self.subTest(overrides=overrides):
                kwargs = {
                    "token_dict": self.token_dict,
                    "quantity": 1,
                    "side": Side.BUY,
                    "product": Product.MIS,
                    "validity": Validity.DAY,
                    "variety": Variety.REGULAR,
                    "unique_id": "invalid-1",
                    "price": 0.0,
                    "trigger": 0.0,
                    "target": 0.0,
                    "stoploss": 0.0,
                    "trailing_sl": 0.0,
                }
                kwargs.update(overrides)

                with self.assertRaises(InputError):
                    self.broker.create_order_any(**kwargs)


if __name__ == "__main__":
    unittest.main()
