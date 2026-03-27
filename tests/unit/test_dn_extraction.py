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
from urllib.parse import quote_plus

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization


# ---------------------------------------------------------------------------
# _escape_dn_value
# ---------------------------------------------------------------------------


def test_escape_plus() -> None:
    from nsi_auth import _escape_dn_value

    assert _escape_dn_value("NTRUS+MI-123456") == r"NTRUS\+MI-123456"


def test_escape_comma() -> None:
    from nsi_auth import _escape_dn_value

    assert _escape_dn_value("a,b") == r"a\,b"


def test_escape_backslash() -> None:
    from nsi_auth import _escape_dn_value

    assert _escape_dn_value("a\\b") == r"a\\b"


def test_escape_double_quote() -> None:
    from nsi_auth import _escape_dn_value

    assert _escape_dn_value('say "hi"') == r'say \"hi\"'


def test_escape_hash_at_start() -> None:
    from nsi_auth import _escape_dn_value

    assert _escape_dn_value("#value") == r"\#value"


def test_escape_hash_not_at_start() -> None:
    from nsi_auth import _escape_dn_value

    assert _escape_dn_value("val#ue") == "val#ue"


def test_escape_leading_space() -> None:
    from nsi_auth import _escape_dn_value

    assert _escape_dn_value(" value") == r"\ value"


def test_escape_trailing_space() -> None:
    from nsi_auth import _escape_dn_value

    assert _escape_dn_value("value ") == r"value\ "


def test_escape_plain_string_unchanged() -> None:
    from nsi_auth import _escape_dn_value

    assert _escape_dn_value("University Corporation") == "University Corporation"


# ---------------------------------------------------------------------------
# extract_dn_from_traefik_header
# ---------------------------------------------------------------------------


def test_traefik_header_valid(application: object) -> None:  # noqa: ARG001
    """Plain (unencoded) Subject= wrapper is handled."""
    from nsi_auth import extract_dn_from_traefik_header

    raw = 'Subject="CN=Test,O=Org,C=US"'
    assert extract_dn_from_traefik_header(raw) == "CN=Test,O=Org,C=US"


def test_traefik_header_url_encoded(application: object) -> None:  # noqa: ARG001
    """URL-encoded form (as Traefik sends it) is decoded correctly."""
    from nsi_auth import extract_dn_from_traefik_header

    encoded = quote_plus('Subject="CN=Test Client,O=Org,C=US"')
    assert extract_dn_from_traefik_header(encoded) == "CN=Test Client,O=Org,C=US"


def test_traefik_header_percent_encoded_chars(application: object) -> None:  # noqa: ARG001
    """Percent-encoded delimiters (%3D %22 %2C) are decoded correctly."""
    from nsi_auth import extract_dn_from_traefik_header

    # Subject%3D%22CN%3DTest%2CO%3DOrg%22 → Subject="CN=Test,O=Org"
    encoded = "Subject%3D%22CN%3DTest%2CO%3DOrg%22"
    assert extract_dn_from_traefik_header(encoded) == "CN=Test,O=Org"


def test_traefik_header_no_subject_wrapper(application: object) -> None:  # noqa: ARG001
    """Header without Subject= wrapper returns None."""
    from nsi_auth import extract_dn_from_traefik_header

    assert extract_dn_from_traefik_header("CN=Test,O=Org,C=US") is None


def test_traefik_header_empty(application: object) -> None:  # noqa: ARG001
    from nsi_auth import extract_dn_from_traefik_header

    assert extract_dn_from_traefik_header("") is None


# ---------------------------------------------------------------------------
# extract_dn_from_pem_header
# ---------------------------------------------------------------------------


def test_pem_header_valid_dn(application: object, pem_header_value: str, test_cert_dn: str) -> None:  # noqa: ARG001
    """Valid PEM header returns correct full DN."""
    from nsi_auth import extract_dn_from_pem_header

    assert extract_dn_from_pem_header(pem_header_value) == test_cert_dn


def test_pem_header_extended_fields_present(application: object, pem_header_value: str) -> None:  # noqa: ARG001
    """organizationIdentifier and emailAddress appear in the extracted DN."""
    from nsi_auth import extract_dn_from_pem_header

    dn = extract_dn_from_pem_header(pem_header_value)
    assert dn is not None
    assert "organizationIdentifier=" in dn
    assert "emailAddress=" in dn


def test_pem_header_plus_escaped(application: object, pem_header_value: str) -> None:  # noqa: ARG001
    """'+' in organizationIdentifier value is escaped as '\\+'."""
    from nsi_auth import extract_dn_from_pem_header

    dn = extract_dn_from_pem_header(pem_header_value)
    assert dn is not None
    assert r"NTRUS\+MI-123456" in dn


def test_pem_header_cert_chain_uses_first_cert(
    application: object, test_cert: x509.Certificate  # noqa: ARG001
) -> None:
    """When header contains a chain, only the first cert's DN is returned."""
    from nsi_auth import extract_dn_from_pem_header

    # Traefik sends concatenated raw DER bytes, base64-encoded, no markers
    der = test_cert.public_bytes(serialization.Encoding.DER)
    chain_b64 = base64.b64encode(der + der).decode("ascii")

    dn = extract_dn_from_pem_header(chain_b64)
    assert dn is not None
    assert "CN=Test Client" in dn


def test_pem_header_garbage_returns_none(application: object) -> None:  # noqa: ARG001
    from nsi_auth import extract_dn_from_pem_header

    assert extract_dn_from_pem_header("not-a-cert") is None


def test_pem_header_valid_base64_but_not_cert(application: object) -> None:  # noqa: ARG001
    """Valid base64 that is not a DER certificate returns None."""
    from nsi_auth import extract_dn_from_pem_header

    assert extract_dn_from_pem_header(base64.b64encode(b"not a cert").decode()) is None


@pytest.mark.parametrize("value", ["", "   ", "%ZZ"])
def test_pem_header_malformed_returns_none(application: object, value: str) -> None:  # noqa: ARG001
    from nsi_auth import extract_dn_from_pem_header

    assert extract_dn_from_pem_header(value) is None
