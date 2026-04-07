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
    """DN in allow-list returns 200 OK."""
    headers = {"ssl-client-subject-dn": "CN=CertA,OU=Dept X,O=Company Y,C=ZZ"}
    response = client.get("/validate", headers=headers)
    assert response.status_code == 200
    assert response.data == b"OK"


def test_validate_with_second_valid_dn_header(client: FlaskClient) -> None:
    """Second allowed DN also returns 200 OK."""
    headers = {"ssl-client-subject-dn": "CN=CertB,OU=Dept X,O=Company Y,C=ZZ"}
    response = client.get("/validate", headers=headers)
    assert response.status_code == 200
    assert response.data == b"OK"


# ---------------------------------------------------------------------------
# Unhappy paths
# ---------------------------------------------------------------------------


def test_validate_without_dn_header(client: FlaskClient) -> None:
    """Missing header returns 403."""
    response = client.get("/validate")
    assert response.status_code == 403
    assert response.data == b"Forbidden"


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


def test_validate_wrong_order_dn_header(client: FlaskClient) -> None:
    """DN in reversed field order (not RFC 2253) returns 403."""
    headers = {"ssl-client-subject-dn": "C=ZZ,O=Company Y,OU=Dept X,CN=CertA"}
    response = client.get("/validate", headers=headers)
    assert response.status_code == 403
    assert response.data == b"Forbidden"


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


def test_validate_reversed_dn_header_not_matched(reversed_client: FlaskClient) -> None:
    """DN not in allow-list returns 403 even with reversed file."""
    headers = {"ssl-client-subject-dn": "CN=Unknown,O=Org,C=NL"}
    response = reversed_client.get("/validate", headers=headers)
    assert response.status_code == 403


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
