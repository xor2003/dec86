from __future__ import annotations

from monkeytype.config import DefaultConfig
from monkeytype.db.sqlite import SQLiteStore

from inertia_decompiler.monkeytype_tools import MONKEYTYPE_DB_PATH, ensure_monkeytype_dirs, monkeytype_code_filter


class InertiaMonkeyTypeConfig(DefaultConfig):
    def trace_store(self):
        ensure_monkeytype_dirs()
        return SQLiteStore.make_store(str(MONKEYTYPE_DB_PATH))

    def code_filter(self):
        return monkeytype_code_filter


CONFIG = InertiaMonkeyTypeConfig()
