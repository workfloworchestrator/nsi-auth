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

"""Functional tests for Traefik X-Forwarded-Tls-Client-Cert-Info header authentication."""

from urllib.parse import quote_plus

from flask.testing import FlaskClient


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


def test_validate_info_header_allowed(info_client: FlaskClient) -> None:
    """URL-encoded Subject= info header with DN in allow-list returns 200 OK."""
    encoded = quote_plus('Subject="CN=Test,O=Org,C=US"')
    response = info_client.get("/validate", headers={"X-Forwarded-Tls-Client-Cert-Info": encoded})
    assert response.status_code == 200
    assert response.data == b"OK"


def test_validate_info_header_plain(info_client: FlaskClient) -> None:
    """Plain (non-URL-encoded) Subject= info header returns 200 OK."""
    raw = 'Subject="CN=Test,O=Org,C=US"'
    response = info_client.get("/validate", headers={"X-Forwarded-Tls-Client-Cert-Info": raw})
    assert response.status_code == 200
    assert response.data == b"OK"


def test_validate_info_header_second_dn(info_client: FlaskClient) -> None:
    """Second allowed DN also returns 200 OK."""
    encoded = quote_plus('Subject="CN=CertB,OU=Dept X,O=Company Y,C=ZZ"')
    response = info_client.get("/validate", headers={"X-Forwarded-Tls-Client-Cert-Info": encoded})
    assert response.status_code == 200
    assert response.data == b"OK"


# ---------------------------------------------------------------------------
# Unhappy paths
# ---------------------------------------------------------------------------


def test_validate_without_info_header(info_client: FlaskClient) -> None:
    """Missing header returns 403."""
    response = info_client.get("/validate")
    assert response.status_code == 403


def test_validate_info_header_not_in_allowlist(info_client: FlaskClient) -> None:
    """DN not in allow-list returns 403."""
    encoded = quote_plus('Subject="CN=SomeoneElse,O=Unknown,C=NL"')
    response = info_client.get("/validate", headers={"X-Forwarded-Tls-Client-Cert-Info": encoded})
    assert response.status_code == 403


def test_validate_info_header_empty(info_client: FlaskClient) -> None:
    """Empty header returns 403."""
    response = info_client.get("/validate", headers={"X-Forwarded-Tls-Client-Cert-Info": ""})
    assert response.status_code == 403


def test_validate_info_header_no_subject_wrapper(info_client: FlaskClient) -> None:
    """Header without Subject= wrapper returns 403."""
    response = info_client.get(
        "/validate", headers={"X-Forwarded-Tls-Client-Cert-Info": "CN=Test,O=Org,C=US"}
    )
    assert response.status_code == 403


def test_validate_wrong_header_name(info_client: FlaskClient) -> None:
    """Sending info via wrong header name returns 403."""
    response = info_client.get(
        "/validate", headers={"ssl-client-subject-dn": "CN=Test,O=Org,C=US"}
    )
    assert response.status_code == 403
