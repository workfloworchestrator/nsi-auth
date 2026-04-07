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
import base64
import datetime
from urllib.parse import quote_plus

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import rfc4514_cmp


# ---------------------------------------------------------------------------
# Session-scoped test certificate
# ---------------------------------------------------------------------------

_OID_ORGANIZATION_IDENTIFIER = x509.ObjectIdentifier("2.5.4.97")


@pytest.fixture(scope="session")
def test_key():
    """RSA key for test certificate generation."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def test_cert(test_key):
    """Self-signed certificate with extended subject fields for testing."""
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
        .public_key(test_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1))
        .sign(test_key, hashes.SHA256())
    )


@pytest.fixture(scope="session")
def traefik_pem_str(test_cert):
    """Traefik-style PEM string: raw base64 DER, no markers, no newlines."""
    der = test_cert.public_bytes(serialization.Encoding.DER)
    return base64.b64encode(der).decode("ascii")


# ---------------------------------------------------------------------------
# subject_dn_from_traefik_cert_info
# ---------------------------------------------------------------------------


def test_traefik_info_valid():
    """Plain (unencoded) Subject= wrapper is handled."""
    raw = 'Subject="CN=Test,O=Org,C=US"'
    result = rfc4514_cmp.subject_dn_from_traefik_cert_info(raw)
    expected = rfc4514_cmp.dn_rfc2253_string_to_rfc4514_name("CN=Test,O=Org,C=US")
    assert result == expected


def test_traefik_info_url_encoded():
    """URL-encoded form (as Traefik sends it) is decoded correctly."""
    encoded = quote_plus('Subject="CN=Test Client,O=Org,C=US"')
    result = rfc4514_cmp.subject_dn_from_traefik_cert_info(encoded)
    expected = rfc4514_cmp.dn_rfc2253_string_to_rfc4514_name("CN=Test Client,O=Org,C=US")
    assert result == expected


def test_traefik_info_percent_encoded_chars():
    """Percent-encoded delimiters (%3D %22 %2C) are decoded correctly."""
    # Subject%3D%22CN%3DTest%2CO%3DOrg%22 -> Subject="CN=Test,O=Org"
    encoded = "Subject%3D%22CN%3DTest%2CO%3DOrg%22"
    result = rfc4514_cmp.subject_dn_from_traefik_cert_info(encoded)
    expected = rfc4514_cmp.dn_rfc2253_string_to_rfc4514_name("CN=Test,O=Org")
    assert result == expected


def test_traefik_info_no_subject_wrapper():
    """Header without Subject= wrapper returns None."""
    assert rfc4514_cmp.subject_dn_from_traefik_cert_info("CN=Test,O=Org,C=US") is None


def test_traefik_info_empty():
    """Empty string returns None."""
    assert rfc4514_cmp.subject_dn_from_traefik_cert_info("") is None


# ---------------------------------------------------------------------------
# subject_dn_from_traefik_cert_pem
# ---------------------------------------------------------------------------


def test_pem_valid_cert(test_cert, traefik_pem_str):
    """Valid Traefik PEM string returns correct x509.Name."""
    result = rfc4514_cmp.subject_dn_from_traefik_cert_pem(traefik_pem_str)
    assert result == test_cert.subject


def test_pem_extended_fields_present(traefik_pem_str):
    """organizationIdentifier and emailAddress appear in the extracted DN."""
    result = rfc4514_cmp.subject_dn_from_traefik_cert_pem(traefik_pem_str)
    oid_values = {attr.oid: attr.value for attr in result}
    assert _OID_ORGANIZATION_IDENTIFIER in oid_values
    assert NameOID.EMAIL_ADDRESS in oid_values
    assert oid_values[_OID_ORGANIZATION_IDENTIFIER] == "NTRUS+MI-123456"
    assert oid_values[NameOID.EMAIL_ADDRESS] == "test@example.com"


def test_pem_garbage_raises():
    """Garbage input raises an exception."""
    with pytest.raises(Exception):
        rfc4514_cmp.subject_dn_from_traefik_cert_pem("not-a-cert")


def test_pem_valid_base64_not_cert_raises():
    """Valid base64 that is not a DER certificate raises an exception."""
    b64 = base64.b64encode(b"not a certificate").decode()
    with pytest.raises(Exception):
        rfc4514_cmp.subject_dn_from_traefik_cert_pem(b64)


@pytest.mark.parametrize("value", ["", "   "])
def test_pem_malformed_raises(value):
    """Empty or whitespace-only input raises an exception."""
    with pytest.raises(Exception):
        rfc4514_cmp.subject_dn_from_traefik_cert_pem(value)
