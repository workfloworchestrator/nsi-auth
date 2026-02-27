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
from collections.abc import Generator
from pathlib import Path

from flask import Flask
from flask.testing import FlaskClient
from pytest import MonkeyPatch, fixture


@fixture
def allowed_client_dn(tmp_path: Path) -> Path:
    """Create a temporary file for testing client DNs."""
    path = tmp_path / "settings.json"
    content = ("CN=CertA,OU=Dept X,O=Company Y,C=ZZ\n"
               "CN=CertB,OU=Dept X,O=Company Y,C=ZZ\n")  # fmt: skip
    path.write_text(content, encoding="utf-8")
    return path


@fixture
def application(allowed_client_dn: Path, monkeypatch: MonkeyPatch) -> Generator[Flask, None, None]:
    """Create and configure a new app instance for each test."""
    monkeypatch.setenv("allowed_client_subject_dn_path", str(allowed_client_dn))
    from nsi_auth import app

    app.config.update(
        {
            "TESTING": True,  # Propagates exceptions to the test suite
            # "allowed_client_subject_dn_path":  allowed_client_dn
        }
    )
    yield app


@fixture
def client(application: Flask) -> FlaskClient:
    """A test client for the application instance."""
    return application.test_client()
