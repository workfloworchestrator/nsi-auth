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

"""Functional tests for nginx ssl-client-subject-dn header authentication."""

import pytest
from flask.testing import FlaskClient


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


def test_validate_with_valid_dn_header(client: FlaskClient) -> None:
    """DN in allow-list returns 200 OK with auth headers."""
    headers = {"ssl-client-subject-dn": "CN=CertA,OU=Dept X,O=Company Y,C=ZZ"}
    response = client.get("/validate", headers=headers)
    assert response.status_code == 200
    assert response.data == b"OK"
    assert response.headers["X-Auth-Method"] == "mTLS"
    assert response.headers["X-Client-DN"] == "CN=CertA,OU=Dept X,O=Company Y,C=ZZ"


def test_validate_with_second_valid_dn_header(client: FlaskClient) -> None:
    """Second allowed DN also returns 200 OK with auth headers."""
    headers = {"ssl-client-subject-dn": "CN=CertB,OU=Dept X,O=Company Y,C=ZZ"}
    response = client.get("/validate", headers=headers)
    assert response.status_code == 200
    assert response.data == b"OK"
    assert response.headers["X-Auth-Method"] == "mTLS"
    assert response.headers["X-Client-DN"] == "CN=CertB,OU=Dept X,O=Company Y,C=ZZ"


# ---------------------------------------------------------------------------
# Unhappy paths
# ---------------------------------------------------------------------------


def test_validate_without_dn_header(client: FlaskClient) -> None:
    """Missing header returns 403 without auth headers."""
    response = client.get("/validate")
    assert response.status_code == 403
    assert response.data == b"Forbidden"
    assert "X-Auth-Method" not in response.headers
    assert "X-Client-DN" not in response.headers


def test_validate_with_empty_dn_header(client: FlaskClient) -> None:
    """Empty header returns 403."""
    response = client.get("/validate", headers={"ssl-client-subject-dn": ""})
    assert response.status_code == 403


def test_validate_with_invalid_dn_header(client: FlaskClient) -> None:
    """DN not in allow-list returns 403."""
    headers = {"ssl-client-subject-dn": "CN=CertA,OU=Dept X,O=Company Y,C=ZZZZZZZZZZ"}
    response = client.get("/validate", headers=headers)
    assert response.status_code == 403


def test_validate_with_unauthorized_escaped_dn_header(client: FlaskClient) -> None:
    """Correct but unauthorized DN with escapes returns 403."""
    headers = {"ssl-client-subject-dn": "CN=CertA,OU=Dept\\,X,O=Company Y,C=ZZ"}
    response = client.get("/validate", headers=headers)
    assert response.status_code == 403


@pytest.mark.parametrize(
    "header_value",
    [
        pytest.param(
            "C=ZZ,O=Company Y,OU=Dept X,CN=CertA",
            id="reversed-rdn-order",
        ),
        pytest.param(
            "OU=Dept X,CN=CertA,C=ZZ,O=Company Y",
            id="shuffled-rdn-order",
        ),
    ],
)
def test_validate_order_independent_matching(client: FlaskClient, header_value: str) -> None:
    """Same identity in any RDN order matches the allowlist (multiset semantics)."""
    response = client.get("/validate", headers={"ssl-client-subject-dn": header_value})
    assert response.status_code == 200
    assert response.data == b"OK"
    assert response.headers["X-Auth-Method"] == "mTLS"


def test_validate_wrong_header_name(client: FlaskClient) -> None:
    """Sending DN via a different header than configured returns 403."""
    headers = {"X-Forwarded-Tls-Client-Cert-Info": 'Subject="CN=CertA,OU=Dept X,O=Company Y,C=ZZ"'}
    response = client.get("/validate", headers=headers)
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# Reversed DN order in allowed file (flexible parsing)
# ---------------------------------------------------------------------------


def test_validate_reversed_dn_in_file_matches_rfc2253_header(reversed_client: FlaskClient) -> None:
    """DN stored in reversed order in file matches RFC 2253 header."""
    headers = {"ssl-client-subject-dn": "CN=CertA,OU=Dept X,O=Company Y,C=ZZ"}
    response = reversed_client.get("/validate", headers=headers)
    assert response.status_code == 200
    assert response.data == b"OK"
    assert response.headers["X-Auth-Method"] == "mTLS"
    assert response.headers["X-Client-DN"] == "CN=CertA,OU=Dept X,O=Company Y,C=ZZ"


def test_validate_reversed_dn_header_not_matched(reversed_client: FlaskClient) -> None:
    """DN not in allow-list returns 403 even with reversed file."""
    headers = {"ssl-client-subject-dn": "CN=Unknown,O=Org,C=NL"}
    response = reversed_client.get("/validate", headers=headers)
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# Go-format DN (Traefik kubernetesIngressNGINX provider, production scenario)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "header_value",
    [
        pytest.param(
            "2.5.4.97=EXAMPLE-12345678,1.2.840.113549.1.9.1=jane.doe@example.com,"
            "2.5.4.4=Doe,2.5.4.42=Jane,C=NL,ST=Utrecht,O=Example Org,CN=Jane Doe",
            id="go-oid-fallback-form",
        ),
        pytest.param(
            "CN=Jane Doe,GN=Jane,SN=Doe,emailAddress=jane.doe@example.com,"
            "organizationIdentifier=EXAMPLE-12345678,O=Example Org,ST=Utrecht,C=NL",
            id="openssl-friendly-form",
        ),
        pytest.param(
            "C=NL,ST=Utrecht,O=Example Org,organizationIdentifier=EXAMPLE-12345678,"
            "emailAddress=jane.doe@example.com,SN=Doe,GN=Jane,CN=Jane Doe",
            id="rfc2253-reversed-form",
        ),
        pytest.param(
            # Traefik's kubernetesIngressNGINX provider (the actual production
            # case): attribute types without friendly names in Go's stdlib are
            # emitted as RFC 4514 `#hexstring` (BER TLV) form. Cryptography's
            # parser stores those bytes verbatim into the NameAttribute.value as
            # a str — without TLV stripping the multiset comparison fails.
            #
            #   2.5.4.42=#13044a616e65  → PrintableString "Jane"  (GN)
            #   2.5.4.4=#1303446f65     → PrintableString "Doe"   (SN)
            #   1.2.840.113549.1.9.1=#0c146a616e652e646f6540657861... → UTF8 email
            #   2.5.4.97=#1310...                                    → organizationIdentifier
            "CN=Jane Doe,O=Example Org,ST=Utrecht,C=NL,"
            "2.5.4.42=#13044a616e65,"
            "2.5.4.4=#1303446f65,"
            "1.2.840.113549.1.9.1=#0c146a616e652e646f65406578616d706c652e636f6d,"
            "2.5.4.97=#13104558414d504c452d3132333435363738",
            id="rfc4514-ber-hexstring-form",
        ),
    ],
)
def test_validate_personal_attrs_matches_any_serialization(
    personal_attrs_client: FlaskClient, header_value: str
) -> None:
    """Same identity in OpenSSL, Go-OID, or RFC 2253 form all match a single allowlist entry."""
    response = personal_attrs_client.get("/validate", headers={"ssl-client-subject-dn": header_value})
    assert response.status_code == 200
    assert response.data == b"OK"
    assert response.headers["X-Auth-Method"] == "mTLS"


# ---------------------------------------------------------------------------
# HTTP method enforcement & routing
# ---------------------------------------------------------------------------


def test_root_not_found(client: FlaskClient) -> None:
    """Root endpoint returns 404."""
    response = client.get("/")
    assert response.status_code == 404


@pytest.mark.parametrize("method", ["post", "put", "delete", "patch"])
def test_validate_rejects_non_get_methods(client: FlaskClient, method: str) -> None:
    """Only GET is allowed on /validate."""
    response = getattr(client, method)("/validate")
    assert response.status_code == 405
