import sys
import types
import unittest
from unittest import mock

from core import registry
from core.config import Config, ConfigError, parse
from core.registry import close, load


def fake(name, **over):
    """Fake module object, injected into sys.modules as modules.<name>."""
    calls = []

    def init(cfg):
        calls.append(("init", cfg))
        return {"name": name}

    def collect(st):
        return {"v": 1, "status": "ok", "summary": "", "panels": [], "events": []}

    def close_fn(st):
        calls.append(("close", st))

    mod = types.ModuleType(f"modules.{name}")
    mod.NAME = name
    mod.INTERVAL = 2.0
    mod.init = init
    mod.collect = collect
    mod.close = close_fn
    for k, v in over.items():
        if v is None and k == "close":
            del mod.close
        else:
            setattr(mod, k, v)
    mod.calls = calls
    return mod


def cfg(text=""):
    return parse(text.encode())


class Base(unittest.TestCase):
    def install(self, mods: dict):
        """mods: import name -> module object or None (None = import fails)."""
        p = mock.patch.dict(sys.modules, mods)
        p.start()
        self.addCleanup(p.stop)
        return list(mods)


class TestLoad(Base):
    def test_default_list_valid(self):
        registry._names(registry.MODULES)
        self.assertEqual(load(Config()), [])

    def test_good(self):
        a = fake("a")
        names = self.install({"modules.a": a})
        [ld] = load(cfg('[modules.a]\nkey = "v"\nnested = {x = [1]}\n'), names)
        self.assertTrue(ld.active)
        self.assertEqual((ld.name, ld.import_name, ld.error), ("a", "modules.a", None))
        self.assertIs(ld.mod, a)
        self.assertEqual(ld.interval, 2.0)
        self.assertEqual(ld.state, {"name": "a"})
        self.assertEqual(a.calls, [("init", {"key": "v", "nested": {"x": [1]}})])

    def test_no_table_empty_options(self):
        a = fake("a")
        [ld] = load(cfg(), self.install({"modules.a": a}))
        self.assertTrue(ld.active)
        self.assertEqual(a.calls, [("init", {})])

    def test_options_copied(self):
        def init(c):
            c["nested"]["x"].append(2)
        c = cfg("[modules.a]\nnested = {x = [1]}\n")
        load(c, self.install({"modules.a": fake("a", init=init)}))
        self.assertEqual(c.module("a").options, {"nested": {"x": [1]}})

    def test_interval_override(self):
        names = self.install({"modules.a": fake("a")})
        [ld] = load(cfg("[modules.a]\ninterval = 5\n"), names)
        self.assertEqual(ld.interval, 5.0)
        self.assertIsInstance(ld.interval, float)

    def test_int_interval_from_module(self):
        [ld] = load(cfg(), self.install({"modules.a": fake("a", INTERVAL=3)}))
        self.assertEqual(ld.interval, 3.0)
        self.assertIsInstance(ld.interval, float)

    def test_disabled_not_imported(self):
        names = self.install({"modules.a": None})     # import would fail
        [ld] = load(cfg("[modules.a]\nenabled = false\n"), names)
        self.assertFalse(ld.enabled)
        self.assertFalse(ld.active)
        self.assertIsNone(ld.mod)
        self.assertIsNone(ld.error)

    def test_import_error(self):
        [ld] = load(cfg(), self.install({"modules.a": None}))
        self.assertFalse(ld.active)
        self.assertIsNone(ld.mod)
        self.assertTrue(ld.error.startswith("import: ModuleNotFoundError"), ld.error)

    def test_check_error(self):
        for over in ({"INTERVAL": 0.5}, {"collect": None}, {"NAME": "B"}):
            with self.subTest(over=over):
                a = fake("a", **over)
                [ld] = load(cfg(), self.install({"modules.a": a}))
                self.assertTrue(ld.error.startswith("check: ValueError"), ld.error)
                self.assertIsNone(ld.mod)
                self.assertEqual(a.calls, [])          # init not called

    def test_name_mismatch(self):
        [ld] = load(cfg(), self.install({"modules.a": fake("b")}))
        self.assertEqual(ld.error, "check: ValueError: NAME 'b' != 'a'")

    def test_init_error(self):
        def boom(c):
            raise RuntimeError("boom")
        [ld] = load(cfg(), self.install({"modules.a": fake("a", init=boom)}))
        self.assertFalse(ld.active)
        self.assertEqual(ld.error, "init: RuntimeError: boom")
        self.assertIsNotNone(ld.mod)

    def test_init_error_no_message(self):
        def boom(c):
            raise OSError
        [ld] = load(cfg(), self.install({"modules.a": fake("a", init=boom)}))
        self.assertEqual(ld.error, "init: OSError")

    def test_init_sys_exit_isolated(self):
        def bye(c):
            sys.exit(3)
        [ld] = load(cfg(), self.install({"modules.a": fake("a", init=bye)}))
        self.assertEqual(ld.error, "init: SystemExit: 3")

    def test_keyboard_interrupt_not_caught(self):
        def intr(c):
            raise KeyboardInterrupt
        names = self.install({"modules.a": fake("a", init=intr)})
        with self.assertRaises(KeyboardInterrupt):
            load(cfg(), names)

    def test_isolation_and_order(self):
        def boom(c):
            raise RuntimeError("x")
        names = self.install({"modules.c": fake("c"), "modules.a": fake("a", init=boom),
                              "modules.b": None, "modules.d": fake("d")})
        out = load(cfg(), names)
        self.assertEqual([ld.name for ld in out], ["c", "a", "b", "d"])
        self.assertEqual([ld.active for ld in out], [True, False, False, True])

    def test_unknown_module_in_config(self):
        a = fake("a")
        names = self.install({"modules.a": a})
        for text in ("[modules.typo]\n", "[modules.typo]\nenabled = false\n"):
            with self.subTest(text=text):
                with self.assertRaisesRegex(ConfigError, "typo"):
                    load(cfg(text), names)
        self.assertEqual(a.calls, [])                  # nothing initialized

    def test_bad_static_list(self):
        for bad in (["firewall"], ["modules.Fire"], ["modules.a.b"], ["core.run"],
                    [1], ["modules.a", "modules.a"]):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    load(Config(), bad)


class TestClose(Base):
    def test_close(self):
        order = []

        def closer(tag):
            def fn(st):
                order.append((tag, st))
            return fn

        def bad_close(st):
            raise RuntimeError("stuck")

        def boom(c):
            raise RuntimeError("x")

        names = self.install({
            "modules.a": fake("a", close=closer("a")),
            "modules.b": fake("b", close=bad_close),
            "modules.c": fake("c", close=None),               # no close
            "modules.d": fake("d", close=closer("d"), init=boom),  # init failed
            "modules.e": fake("e", close=closer("e")),
        })
        out = load(cfg("[modules.e]\nenabled = false\n"), names)
        errors = close(out)
        self.assertEqual(order, [("a", {"name": "a"})])      # d, e skipped
        self.assertEqual(errors, [("b", "close: RuntimeError: stuck")])

    def test_reverse_order(self):
        order = []
        names = self.install({
            "modules.a": fake("a", close=lambda st: order.append("a")),
            "modules.b": fake("b", close=lambda st: order.append("b")),
        })
        close(load(cfg(), names))
        self.assertEqual(order, ["b", "a"])


if __name__ == "__main__":
    unittest.main()
