#  Copyright 2026 SURF.
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
import threading
from pathlib import Path

import pytest
from flask import Flask

TIMEOUT = 10.0
POLL_INTERVAL = 0.1


def write_until_seen(path: Path, mode: str, seen: threading.Event) -> bool:
    """Write to `path` every POLL_INTERVAL until `seen` is set or TIMEOUT expires.

    Retrying instead of sleeping once: the watch may not be live yet when the first write happens.
    """

    def attempt() -> bool:
        with path.open(mode, encoding="utf-8") as f:
            f.write("CN=Written,OU=Dept X,O=Company Y,C=ZZ\n")
        return seen.wait(POLL_INTERVAL)

    return any(attempt() for _ in range(round(TIMEOUT / POLL_INTERVAL)))


@pytest.mark.parametrize("mode", [pytest.param("a", id="append"), pytest.param("w", id="rewrite")])
def test_watchdog_file_calls_callback_on_in_place_write(application: Flask, tmp_path: Path, mode: str) -> None:
    """Verify that a real observer reports an in-place write to the watched file and then stops."""
    from nsi_auth import watchdog_file

    watched = tmp_path / "watched_dn.txt"
    watched.touch()

    seen = threading.Event()
    observer = watchdog_file(watched, lambda _path: seen.set())
    try:
        assert write_until_seen(watched, mode, seen)
    finally:
        observer.stop()
        observer.join(timeout=TIMEOUT)

    assert not observer.is_alive()
