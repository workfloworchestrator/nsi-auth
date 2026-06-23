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
from pytest import fixture

from tests.conftest import make_application


# ---------------------------------------------------------------------------
# Traefik PEM cert header fixtures
# ---------------------------------------------------------------------------

@fixture
def cert_allowed_client_dn(tmp_path: Path) -> Path:
    """Allowed DNs for Traefik PEM cert tests."""
    path = tmp_path / "allowed_dn.txt"
    content = (
        "CN=Good CA,O=Test Certificates 2011,C=US\n"
        "CN=University Corporation For Advanced Internet Development,"
        "emailAddress=knewell@internet2.edu,"
        "organizationIdentifier=NTRUS\\+MI-801069584,"
        "O=University Corporation For Advanced Internet Development,"
        "ST=Michigan,C=US\n"
    )
    path.write_text(content, encoding="utf-8")
    return path


@fixture
def cert_application(cert_allowed_client_dn: Path) -> Generator[Flask, None, None]:
    """App configured for Traefik PEM cert header auth."""
    yield from make_application(cert_allowed_client_dn, "X-Forwarded-Tls-Client-Cert", "traefik-pem")


@fixture
def cert_client(cert_application: Flask) -> FlaskClient:
    """Test client for Traefik PEM cert header auth."""
    return cert_application.test_client()


# ---------------------------------------------------------------------------
# Traefik Cert-Info header fixtures
# ---------------------------------------------------------------------------

@fixture
def info_allowed_client_dn(tmp_path: Path) -> Path:
    """Allowed DNs for Traefik Cert-Info tests."""
    path = tmp_path / "allowed_dn.txt"
    content = ("CN=Test,O=Org,C=US\n"
               "CN=CertB,OU=Dept X,O=Company Y,C=ZZ\n")  # fmt: skip
    path.write_text(content, encoding="utf-8")
    return path


@fixture
def info_application(info_allowed_client_dn: Path) -> Generator[Flask, None, None]:
    """App configured for Traefik Cert-Info header auth."""
    yield from make_application(info_allowed_client_dn, "X-Forwarded-Tls-Client-Cert-Info", "traefik-info")


@fixture
def info_client(info_application: Flask) -> FlaskClient:
    """Test client for Traefik Cert-Info header auth."""
    return info_application.test_client()


# ---------------------------------------------------------------------------
# Reversed DN order fixtures (for flexible file parsing tests)
# ---------------------------------------------------------------------------

@fixture
def reversed_allowed_client_dn(tmp_path: Path) -> Path:
    """Allowed DNs with reversed (small-to-big) field order."""
    path = tmp_path / "allowed_dn.txt"
    content = ("C=ZZ,O=Company Y,OU=Dept X,CN=CertA\n"
               "CN=CertB,OU=Dept X,O=Company Y,C=ZZ\n")  # fmt: skip
    path.write_text(content, encoding="utf-8")
    return path


@fixture
def reversed_application(reversed_allowed_client_dn: Path) -> Generator[Flask, None, None]:
    """App configured for nginx auth with reversed DN order in allowed file."""
    yield from make_application(reversed_allowed_client_dn, "ssl-client-subject-dn")


@fixture
def reversed_client(reversed_application: Flask) -> FlaskClient:
    """Test client for reversed DN order tests."""
    return reversed_application.test_client()


# ---------------------------------------------------------------------------
# Personal-attribute fixtures (Go OID-fallback form, real production case)
# ---------------------------------------------------------------------------

@fixture
def personal_attrs_allowed_client_dn(tmp_path: Path) -> Path:
    """Allowlist with personal attrs in operator-friendly OpenSSL form."""
    path = tmp_path / "allowed_dn.txt"
    content = (
        "CN=Jane Doe,GN=Jane,SN=Doe,"
        "emailAddress=jane.doe@example.com,"
        "organizationIdentifier=EXAMPLE-12345678,"
        "O=Example Org,ST=Utrecht,C=NL\n"
    )
    path.write_text(content, encoding="utf-8")
    return path


@fixture
def personal_attrs_application(personal_attrs_allowed_client_dn: Path) -> Generator[Flask, None, None]:
    """App configured for nginx auth with personal-attr DN allowlist."""
    yield from make_application(personal_attrs_allowed_client_dn, "ssl-client-subject-dn")


@fixture
def personal_attrs_client(personal_attrs_application: Flask) -> FlaskClient:
    """Test client for personal-attr DN matching."""
    return personal_attrs_application.test_client()


# ---------------------------------------------------------------------------
# Standard-PEM and Envoy XFCC fixtures (generic codecs, any header name)
# ---------------------------------------------------------------------------

# Subject of the Good CA test certificate (see test_pem.GOOD_CA_PEM).
GOOD_CA_DN = "CN=Good CA,O=Test Certificates 2011,C=US"


@fixture
def good_ca_allowed_client_dn(tmp_path: Path) -> Path:
    """Allowlist holding the Good CA DN (for pem / xfcc-cert codecs)."""
    path = tmp_path / "allowed_dn.txt"
    path.write_text(GOOD_CA_DN + "\n", encoding="utf-8")
    return path


@fixture
def pem_application(good_ca_allowed_client_dn: Path) -> Generator[Flask, None, None]:
    """App configured for a standard PEM certificate under an arbitrary header."""
    yield from make_application(good_ca_allowed_client_dn, "ssl-client-cert", "pem")


@fixture
def pem_client(pem_application: Flask) -> FlaskClient:
    """Test client for the standard-PEM codec."""
    return pem_application.test_client()


@fixture
def xfcc_cert_application(good_ca_allowed_client_dn: Path) -> Generator[Flask, None, None]:
    """App configured for the Envoy XFCC Cert= codec."""
    yield from make_application(good_ca_allowed_client_dn, "x-forwarded-client-cert", "xfcc-cert")


@fixture
def xfcc_cert_client(xfcc_cert_application: Flask) -> FlaskClient:
    """Test client for the XFCC Cert= codec."""
    return xfcc_cert_application.test_client()


@fixture
def xfcc_subject_application(info_allowed_client_dn: Path) -> Generator[Flask, None, None]:
    """App configured for the Envoy XFCC Subject= codec (reuses CN=Test,O=Org,C=US)."""
    yield from make_application(info_allowed_client_dn, "x-forwarded-client-cert", "xfcc-subject")


@fixture
def xfcc_subject_client(xfcc_subject_application: Flask) -> FlaskClient:
    """Test client for the XFCC Subject= codec."""
    return xfcc_subject_application.test_client()
