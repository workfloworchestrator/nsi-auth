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
import datetime
from collections.abc import Generator
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from flask import Flask
from flask.testing import FlaskClient
from pytest import MonkeyPatch, fixture

_OID_ORGANIZATION_IDENTIFIER = x509.ObjectIdentifier("2.5.4.97")


@fixture
def allowed_client_dn(tmp_path: Path) -> Path:
    """Create a temporary file for testing client DNs."""
    path = tmp_path / "settings.json"
    content = ("CN=CertA,OU=Dept X,O=Company Y,C=Z\n"
               "CN=CertB,OU=Dept X,O=Company Y,C=Z\n")  # fmt: skip
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


@fixture(scope="session")
def test_cert() -> x509.Certificate:
    """Self-signed certificate with extended subject fields for testing."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Michigan"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Organization"),
        x509.NameAttribute(_OID_ORGANIZATION_IDENTIFIER, "NTRUS+MI-123456"),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, "test@example.com"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Test Client"),
    ])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )


@fixture(scope="session")
def test_cert_dn() -> str:
    """Expected DN string for test_cert (DER field order, RFC 4514 escaped)."""
    return r"C=US,ST=Michigan,O=Test Organization,organizationIdentifier=NTRUS\+MI-123456,emailAddress=test@example.com,CN=Test Client"


@fixture(scope="session")
def pem_header_value(test_cert: x509.Certificate) -> str:
    """Traefik X-Forwarded-Tls-Client-Cert header value for test_cert.

    Traefik sends raw base64 DER with no PEM markers and no URL-encoding.
    """
    import base64
    return base64.b64encode(test_cert.public_bytes(serialization.Encoding.DER)).decode("ascii")
