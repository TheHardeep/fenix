import importlib.util
import logging
from pathlib import Path
import sys
import types
import unittest


pyotp_module = types.ModuleType("pyotp")


class _DummyTOTP:
    def __init__(self, *args, **kwargs):
        pass


pyotp_module.TOTP = _DummyTOTP
sys.modules.setdefault("pyotp", pyotp_module)


ROOT_DIR = Path(__file__).resolve().parents[1]
FENIX_DIR = ROOT_DIR / "fenix"
BASE_DIR = FENIX_DIR / "base"
PAPER_DIR = FENIX_DIR / "paper"


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

fenix_paper_package = types.ModuleType("fenix.paper")
fenix_paper_package.__path__ = [str(PAPER_DIR)]
sys.modules.setdefault("fenix.paper", fenix_paper_package)

constants_module = _load_module("fenix.base.constants", BASE_DIR / "constants.py")
errors_module = _load_module("fenix.base.errors", BASE_DIR / "errors.py")
broker_module = _load_module("fenix.base.broker", BASE_DIR / "broker.py")
matching_module = _load_module(
    "fenix.paper.matching_engine",
    PAPER_DIR / "matching_engine.py",
)
state_module = _load_module("fenix.paper.state", PAPER_DIR / "state.py")
client_module = _load_module("fenix.paper.client", PAPER_DIR / "client.py")
paper_module = _load_module("fenix.paper", PAPER_DIR / "__init__.py")
aliceblue_module = _load_module("fenix.aliceblue", FENIX_DIR / "aliceblue.py")

fenix_package.base = fenix_base_package
fenix_package.paper = paper_module
fenix_base_package.constants = constants_module
fenix_base_package.errors = errors_module
fenix_base_package.broker = broker_module
paper_module.matching_engine = matching_module
paper_module.state = state_module
paper_module.client = client_module


AliceBlue = aliceblue_module.AliceBlue
InputError = errors_module.InputError
InvalidOrderError = errors_module.InvalidOrderError
Order = constants_module.Order
Position = constants_module.Position
Side = constants_module.Side
Status = constants_module.Status


class PaperLoggingTests(unittest.TestCase):
    def setUp(self):
        self.logger = logging.getLogger(f"fenix.tests.paper.{self._testMethodName}")
        self.token_dict = {
            "Token": 987654,
            "Symbol": "TESTSTOCK",
            "Exchange": "NSE",
        }

    def _broker(self, **config):
        return AliceBlue({
            "paper_mode": True,
            "logger": self.logger,
            "enableRateLimit": False,
            "enableLastJsonResponse": True,
            **config,
        })

    def test_paper_order_logs_redacted_request_response_and_snapshots(self):
        broker = self._broker()
        broker.authenticate()

        with self.assertLogs(self.logger, level="DEBUG") as captured:
            result = broker.place_order(
                token_dict=self.token_dict,
                quantity=1,
                side=Side.BUY,
                product="MIS",
                validity="DAY",
                variety="REGULAR",
                unique_id="paper-log-1",
            )

        logs = "\n".join(captured.output)
        self.assertIn("paper place_order Request", logs)
        self.assertIn("paper place_order Response", logs)
        self.assertIn("***", logs)
        self.assertNotIn("987654", logs)

        self.assertEqual(broker.last_paper_interaction["operation"], "place_order")
        self.assertEqual(broker.last_paper_interaction["status"], "OK")
        self.assertEqual(broker.last_request_url, "paper://AliceBlue/place_order")
        self.assertEqual(broker.last_request_headers, {"paper": "true"})
        self.assertEqual(broker.last_paper_request["unique_id"], "paper-log-1")
        self.assertEqual(broker.last_paper_response, result)
        self.assertEqual(broker.last_json_response, result)

    def test_paper_errors_are_logged_and_snapshotted(self):
        broker = self._broker()

        with self.assertLogs(self.logger, level="DEBUG") as captured:
            with self.assertRaises(InputError):
                broker.place_order(
                    token_dict=self.token_dict,
                    quantity=1,
                    side="HOLD",
                    product="MIS",
                    validity="DAY",
                    variety="REGULAR",
                    unique_id="bad-side",
                )

        logs = "\n".join(captured.output)
        self.assertIn("paper place_order Response", logs)
        self.assertIn("ERROR", logs)
        self.assertEqual(broker.last_paper_interaction["status"], "ERROR")
        self.assertEqual(
            broker.last_paper_response["error"]["type"],
            "InputError",
        )

    def test_stop_trigger_equal_to_ltp_is_rejected(self):
        broker = self._broker()
        broker.on_tick(token=987654, ltp=100.0)

        with self.assertRaises(InvalidOrderError):
            broker.place_order(
                token_dict=self.token_dict,
                quantity=1,
                side=Side.BUY,
                price=105.0,
                trigger=100.0,
                product="MIS",
                validity="DAY",
                variety="REGULAR",
                unique_id="through-market",
            )

    def test_square_off_cannot_overshoot_open_net_quantity(self):
        broker = self._broker()
        broker.on_tick(token=987654, ltp=100.0)
        broker.place_order(
            token_dict=self.token_dict,
            quantity=1,
            side=Side.BUY,
            product="MIS",
            validity="DAY",
            variety="REGULAR",
            unique_id="long-one",
        )

        with self.assertRaises(InvalidOrderError):
            broker.square_off_position(
                symbol="TESTSTOCK",
                token=987654,
                exchange="NSE",
                quantity=2,
                product="MIS",
            )

    def test_on_tick_returns_copies_not_mutable_internal_orders(self):
        broker = self._broker()
        order_id = broker.place_order(
            token_dict=self.token_dict,
            quantity=1,
            side=Side.BUY,
            product="MIS",
            validity="DAY",
            variety="REGULAR",
            unique_id="copy-check",
        )[Order.ID]

        filled = broker.on_tick(token=987654, ltp=100.0)
        filled[0][Order.STATUS] = "MUTATED"

        self.assertEqual(broker.fetch_order(order_id)[Order.STATUS], Status.FILLED)

    def test_position_average_and_mtm_survive_partial_exit_and_reentry(self):
        broker = self._broker()
        broker.on_tick(token=987654, ltp=100.0)
        broker.place_order(
            token_dict=self.token_dict,
            quantity=10,
            side=Side.BUY,
            product="MIS",
            validity="DAY",
            variety="REGULAR",
            unique_id="buy-ten",
        )

        broker.on_tick(token=987654, ltp=110.0)
        broker.place_order(
            token_dict=self.token_dict,
            quantity=5,
            side=Side.SELL,
            product="MIS",
            validity="DAY",
            variety="REGULAR",
            unique_id="sell-five",
        )

        broker.on_tick(token=987654, ltp=120.0)
        broker.place_order(
            token_dict=self.token_dict,
            quantity=5,
            side=Side.BUY,
            product="MIS",
            validity="DAY",
            variety="REGULAR",
            unique_id="buy-five",
        )

        position = broker.fetch_day_positions()[0]
        self.assertEqual(position[Position.NET_QTY], 10)
        self.assertEqual(position[Position.AVG_PRICE], 110.0)
        self.assertEqual(position[Position.MTM], 100.0)
        self.assertEqual(position[Position.PNL], 150.0)
        self.assertEqual(position[Position.INFO]["realised_pnl"], 50.0)


if __name__ == "__main__":
    unittest.main()
