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
import os
from collections.abc import Generator
from pathlib import Path

from flask import Flask
from flask.testing import FlaskClient
from pytest import fixture


@fixture
def allowed_client_dn(tmp_path: Path) -> Path:
    """Create a temporary file with default test DNs."""
    path = tmp_path / "allowed_dn.txt"
    content = ("CN=CertA,OU=Dept X,O=Company Y,C=ZZ\n"
               "CN=CertB,OU=Dept X,O=Company Y,C=ZZ\n")  # fmt: skip
    path.write_text(content, encoding="utf-8")
    return path


def make_application(allowed_dn_path: Path, header: str) -> Generator[Flask, None, None]:
    """Configure and yield the Flask app for a specific header type.

    Handles both the initial import (via env vars) and subsequent
    reconfigurations (via direct settings mutation).
    """
    os.environ["allowed_client_subject_dn_path"] = str(allowed_dn_path)
    os.environ["tls_client_subject_authn_header"] = header

    from nsi_auth import app, load_allowed_client_dn, settings, state

    old_header = settings.tls_client_subject_authn_header
    old_dns = state.allowed_client_subject_dn_names[:]

    settings.tls_client_subject_authn_header = header
    load_allowed_client_dn(allowed_dn_path)

    app.config["TESTING"] = True
    yield app

    settings.tls_client_subject_authn_header = old_header
    state.allowed_client_subject_dn_names = old_dns


@fixture
def application(allowed_client_dn: Path) -> Generator[Flask, None, None]:
    """App configured for nginx header auth (default for unit tests)."""
    yield from make_application(allowed_client_dn, "ssl-client-subject-dn")


@fixture
def client(application: Flask) -> FlaskClient:
    """A test client for the application instance."""
    return application.test_client()
