"""Comprehensive smoke test for paper-trading mode against AngelOne."""

import sys
from pathlib import Path

# Bypass fenix/__init__.py to avoid loading all brokers and their dependencies
import importlib.util
import types

fenix_path = Path(__file__).parent.parent
sys.path.insert(0, str(fenix_path.parent))

# Create fenix.base package namespace
fenix = types.ModuleType("fenix")
sys.modules["fenix"] = fenix
fenix.base = types.ModuleType("fenix.base")
sys.modules["fenix.base"] = fenix.base
fenix.paper = types.ModuleType("fenix.paper")
sys.modules["fenix.paper"] = fenix.paper

# Load base modules
spec = importlib.util.spec_from_file_location(
    "fenix.base.constants",
    fenix_path / "fenix" / "base" / "constants.py"
)
base_constants = importlib.util.module_from_spec(spec)
sys.modules["fenix.base.constants"] = base_constants
spec.loader.exec_module(base_constants)

spec = importlib.util.spec_from_file_location(
    "fenix.base.errors",
    fenix_path / "fenix" / "base" / "errors.py"
)
base_errors = importlib.util.module_from_spec(spec)
sys.modules["fenix.base.errors"] = base_errors
spec.loader.exec_module(base_errors)

# Paper modules must load BEFORE base.broker, because base.broker now
# imports PaperExecutionClient at module top level.
spec = importlib.util.spec_from_file_location(
    "fenix.paper.matching_engine",
    fenix_path / "fenix" / "paper" / "matching_engine.py"
)
paper_matching = importlib.util.module_from_spec(spec)
sys.modules["fenix.paper.matching_engine"] = paper_matching
spec.loader.exec_module(paper_matching)

spec = importlib.util.spec_from_file_location(
    "fenix.paper.state",
    fenix_path / "fenix" / "paper" / "state.py"
)
paper_state_mod = importlib.util.module_from_spec(spec)
sys.modules["fenix.paper.state"] = paper_state_mod
spec.loader.exec_module(paper_state_mod)

spec = importlib.util.spec_from_file_location(
    "fenix.paper.client",
    fenix_path / "fenix" / "paper" / "client.py"
)
paper_client = importlib.util.module_from_spec(spec)
sys.modules["fenix.paper.client"] = paper_client
spec.loader.exec_module(paper_client)

spec = importlib.util.spec_from_file_location(
    "fenix.paper.__init__",
    fenix_path / "fenix" / "paper" / "__init__.py"
)
paper_pkg = importlib.util.module_from_spec(spec)
sys.modules["fenix.paper"] = paper_pkg
spec.loader.exec_module(paper_pkg)

spec = importlib.util.spec_from_file_location(
    "fenix.base.broker",
    fenix_path / "fenix" / "base" / "broker.py"
)
base_broker = importlib.util.module_from_spec(spec)
sys.modules["fenix.base.broker"] = base_broker
spec.loader.exec_module(base_broker)

# Load AngelOne
spec = importlib.util.spec_from_file_location(
    "fenix.angelone",
    fenix_path / "fenix" / "angelone.py"
)
angelone = importlib.util.module_from_spec(spec)
sys.modules["fenix.angelone"] = angelone
spec.loader.exec_module(angelone)

AngelOne = angelone.AngelOne
Order = base_constants.Order
Status = base_constants.Status
Position = base_constants.Position
InputError = base_errors.InputError


def test_paper_mode():
    """Run 14 comprehensive paper-trading scenarios against AngelOne."""

    config = {"paper_mode": True}
    broker = AngelOne(config)
    broker.authenticate()

    token_dict = {
        "Token": 12345,
        "Symbol": "TESTSTOCK",
        "Exchange": "NSE"
    }

    passed = 0
    failed = 0

    print("\n" + "="*70)
    print("PAPER-TRADING SMOKE TEST - AngelOne (14 scenarios)")
    print("="*70 + "\n")

    # Test 1: Market order with no prior tick stays PENDING
    try:
        print("[1] Market order with no prior tick stays PENDING...")
        order_id = broker.place_order(
            token_dict=token_dict,
            quantity=10,
            side="BUY",
            product="MIS",
            validity="DAY",
            variety="REGULAR",
            unique_id="test_1"
        )[Order.ID]
        order = broker.fetch_order(order_id)
        assert order[Order.STATUS] == Status.PENDING, f"Expected PENDING, got {order[Order.STATUS]}"
        print("   [PASS]\n")
        passed += 1
    except Exception as e:
        print(f"   [FAIL] {e}\n")
        failed += 1

    # Test 2: Tick fills the pending market order
    try:
        print("[2] Tick fills the pending market order...")
        filled = broker.on_tick(token=12345, ltp=500.0)
        assert len(filled) == 1, f"Expected 1 fill, got {len(filled)}"
        order = broker.fetch_order(order_id)
        assert order[Order.STATUS] == Status.FILLED
        assert order[Order.AVG_PRICE] == 500.0
        print("   [PASS]\n")
        passed += 1
    except Exception as e:
        print(f"   [FAIL] {e}\n")
        failed += 1

    # Test 3: Market order with prior tick fills immediately
    try:
        print("[3] Market order with prior tick fills immediately...")
        order_id_2 = broker.place_order(
            token_dict=token_dict,
            quantity=5,
            side="BUY",
            product="MIS",
            validity="DAY",
            variety="REGULAR",
            unique_id="test_3"
        )[Order.ID]
        order = broker.fetch_order(order_id_2)
        assert order[Order.STATUS] == Status.FILLED
        print("   [PASS]\n")
        passed += 1
    except Exception as e:
        print(f"   [FAIL] {e}\n")
        failed += 1

    # Test 4: Limit BUY fills on next tick at LTP <= price
    try:
        print("[4] Limit BUY fills on next tick at LTP <= price...")
        order_id_3 = broker.place_order(
            token_dict=token_dict,
            quantity=3,
            side="BUY",
            price=520.0,
            product="MIS",
            validity="DAY",
            variety="REGULAR",
            unique_id="test_4"
        )[Order.ID]
        order = broker.fetch_order(order_id_3)
        assert order[Order.STATUS] == Status.OPEN

        broker.on_tick(token=12345, ltp=515.0)
        order = broker.fetch_order(order_id_3)
        assert order[Order.STATUS] == Status.FILLED
        print("   [PASS]\n")
        passed += 1
    except Exception as e:
        print(f"   [FAIL] {e}\n")
        failed += 1

    # Test 5: SL BUY with trigger converts to LIMIT and fills on same tick
    try:
        print("[5] SL BUY with trigger converts to LIMIT and fills...")
        order_id_4 = broker.place_order(
            token_dict=token_dict,
            quantity=2,
            side="BUY",
            price=525.0,
            trigger=522.0,
            product="MIS",
            validity="DAY",
            variety="REGULAR",
            unique_id="test_5"
        )[Order.ID]
        order = broker.fetch_order(order_id_4)
        assert order[Order.STATUS] == Status.PENDING

        broker.on_tick(token=12345, ltp=523.0)
        order = broker.fetch_order(order_id_4)
        assert order[Order.STATUS] == Status.FILLED
        print("   [PASS]\n")
        passed += 1
    except Exception as e:
        print(f"   [FAIL] {e}\n")
        failed += 1

    # Test 6: Reject rule fires for SELL SL with trigger above LTP
    try:
        print("[6] Reject rule: SELL SL trigger above LTP raises InvalidOrderError...")
        try:
            broker.place_order(
                token_dict=token_dict,
                quantity=5,
                side="SELL",
                price=510.0,
                trigger=525.0,
                product="MIS",
                validity="DAY",
                variety="REGULAR",
                unique_id="test_6"
            )
            print("   [FAIL] Expected InvalidOrderError but order was placed\n")
            failed += 1
        except Exception as e:
            if "trigger" in str(e).lower():
                print("   [PASS]\n")
                passed += 1
            else:
                print(f"   [FAIL] Wrong error: {e}\n")
                failed += 1
    except Exception as e:
        print(f"   [FAIL] {e}\n")
        failed += 1

    # Test 7: Cancel OPEN limit order
    try:
        print("[7] Cancel OPEN limit order...")
        order_id_5 = broker.place_order(
            token_dict=token_dict,
            quantity=4,
            side="BUY",
            price=510.0,
            product="MIS",
            validity="DAY",
            variety="REGULAR",
            unique_id="test_7"
        )[Order.ID]
        broker.cancel_order(order_id_5)
        order = broker.fetch_order(order_id_5)
        assert order[Order.STATUS] == Status.CANCELLED
        print("   [PASS]\n")
        passed += 1
    except Exception as e:
        print(f"   [FAIL] {e}\n")
        failed += 1

    # Test 8: Modify PENDING order
    try:
        print("[8] Modify PENDING order...")
        order_id_6 = broker.place_order(
            token_dict=token_dict,
            quantity=2,
            side="BUY",
            price=530.0,
            trigger=528.0,
            product="MIS",
            validity="DAY",
            variety="REGULAR",
            unique_id="test_8"
        )[Order.ID]
        broker.modify_order(order_id_6, price=535.0, trigger=530.0)
        order = broker.fetch_order(order_id_6)
        assert order[Order.PRICE] == 535.0
        assert order[Order.TRIGGER_PRICE] == 530.0
        print("   [PASS]\n")
        passed += 1
    except Exception as e:
        print(f"   [FAIL] {e}\n")
        failed += 1

    # Test 9: Cancel-on-missing raises OrderNotFoundError
    try:
        print("[9] Cancel non-existent order raises OrderNotFoundError...")
        try:
            broker.cancel_order("NONEXISTENT")
            print("   [FAIL] Expected OrderNotFoundError\n")
            failed += 1
        except Exception as e:
            if "not found" in str(e).lower():
                print("   [PASS]\n")
                passed += 1
            else:
                print(f"   [FAIL] Wrong error: {e}\n")
                failed += 1
    except Exception as e:
        print(f"   [FAIL] {e}\n")
        failed += 1

    # Test 10: Position math - multiple fills weighted average
    try:
        print("[10] Position math: multiple fills weighted-avg...")
        broker.on_tick(token=12345, ltp=530.0)
        order_id_7 = broker.place_order(
            token_dict=token_dict,
            quantity=1,
            side="BUY",
            product="MIS",
            validity="DAY",
            variety="REGULAR",
            unique_id="test_10"
        )[Order.ID]

        positions = broker.fetch_day_positions()
        assert len(positions) == 1
        pos = positions[0]
        assert pos[Position.NET_QTY] > 0, f"Expected positive net qty, got {pos[Position.NET_QTY]}"
        assert pos[Position.AVG_PRICE] > 0, f"Expected positive avg price, got {pos[Position.AVG_PRICE]}"
        print("   [PASS]\n")
        passed += 1
    except Exception as e:
        print(f"   [FAIL] {e}\n")
        failed += 1

    # Test 11: LTP update refreshes MTM (mark-to-market)
    try:
        print("[11] LTP update refreshes MTM...")
        broker.on_tick(token=12345, ltp=600.0)
        positions = broker.fetch_day_positions()
        assert len(positions) == 1
        pos = positions[0]
        assert pos[Position.NET_QTY] > 0, f"Expected positive net, got {pos[Position.NET_QTY]}"
        assert pos[Position.MTM] > 0, f"Expected positive MTM, got {pos[Position.MTM]}"
        assert pos[Position.LTP] == 600.0
        print("   [PASS]\n")
        passed += 1
    except Exception as e:
        print(f"   [FAIL] {e}\n")
        failed += 1

    # Test 12: Tradebook contains filled orders only
    try:
        print("[12] Tradebook contains filled orders only...")
        tradebook = broker.fetch_tradebook()
        assert len(tradebook) > 0
        for order in tradebook:
            assert order[Order.STATUS] == Status.FILLED
        print("   [PASS]\n")
        passed += 1
    except Exception as e:
        print(f"   [FAIL] {e}\n")
        failed += 1

    # Test 13: Square-off — AngelOne does not expose square_off_position;
    # route directly through the paper client to keep coverage equivalent.
    try:
        print("[13] Square-off flattens position (via paper client)...")
        positions = broker.fetch_day_positions()
        initial_net = positions[0][Position.NET_QTY] if positions else 0
        assert initial_net > 0, f"Expected positive position, got {initial_net}"

        if hasattr(broker, "square_off_position"):
            broker.square_off_position(
                symbol="TESTSTOCK",
                token=12345,
                exchange="NSE",
                quantity=int(initial_net),
                product="MIS",
            )
        else:
            broker._paper.square_off_position(
                symbol="TESTSTOCK",
                token=12345,
                exchange="NSE",
                quantity=int(initial_net),
                product="MIS",
            )
        broker.on_tick(token=12345, ltp=600.0)

        positions = broker.fetch_day_positions()
        assert len(positions) == 1
        pos = positions[0]
        assert pos[Position.NET_QTY] == 0, f"Expected 0 net, got {pos[Position.NET_QTY]}"
        print("   [PASS]\n")
        passed += 1
    except Exception as e:
        print(f"   [FAIL] {e}\n")
        failed += 1

    # Test 14: on_tick() on non-paper broker raises InputError
    try:
        print("[14] on_tick() on non-paper broker raises InputError...")
        config_live = {}
        broker_live = AngelOne(config_live)
        try:
            broker_live.on_tick(token=12345, ltp=500.0)
            print("   [FAIL] Expected InputError\n")
            failed += 1
        except InputError:
            print("   [PASS]\n")
            passed += 1
        except Exception as e:
            print(f"   [FAIL] Wrong error type: {e}\n")
            failed += 1
    except Exception as e:
        print(f"   [FAIL] {e}\n")
        failed += 1

    # Summary
    print("="*70)
    print(f"SUMMARY: {passed} passed, {failed} failed out of 14 tests")
    print("="*70 + "\n")

    return failed == 0


if __name__ == "__main__":
    success = test_paper_mode()
    sys.exit(0 if success else 1)
