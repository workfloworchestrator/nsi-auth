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
from urllib.parse import quote_plus

from flask.testing import FlaskClient


def test_root_not_found(client: FlaskClient) -> None:
    """Verify that the root endpoint returns 404."""
    response = client.get("/")
    assert response.status_code == 404


def test_validate_without_info_header(client: FlaskClient) -> None:
    """Verify that the /validate endpoint returns 403 without Cert-Info header."""
    response = client.get("/validate")
    assert response.status_code == 403


def test_validate_info_header_allowed(client: FlaskClient) -> None:
    """URL-encoded Subject= info header with DN in allow-list returns 200."""
    encoded = quote_plus('Subject="CN=Test,O=Org,C=US"')
    response = client.get("/validate", headers={"X-Forwarded-Tls-Client-Cert-Info": encoded})
    assert response.status_code == 200
    assert response.data == b"OK"


def test_validate_info_header_not_in_allowlist(client: FlaskClient) -> None:
    """URL-encoded Subject= info header with DN not in allow-list returns 403."""
    encoded = quote_plus('Subject="CN=SomeoneElse,O=Unknown,C=NL"')
    response = client.get("/validate", headers={"X-Forwarded-Tls-Client-Cert-Info": encoded})
    assert response.status_code == 403


def test_validate_info_header_plain(client: FlaskClient) -> None:
    """Plain (non-URL-encoded) Subject= info header with DN in allow-list returns 200."""
    raw = 'Subject="CN=Test,O=Org,C=US"'
    response = client.get("/validate", headers={"X-Forwarded-Tls-Client-Cert-Info": raw})
    assert response.status_code == 200
    assert response.data == b"OK"


def test_validate_info_header_empty(client: FlaskClient) -> None:
    """Empty Cert-Info header returns 403."""
    response = client.get("/validate", headers={"X-Forwarded-Tls-Client-Cert-Info": ""})
    assert response.status_code == 403


def test_validate_info_header_no_subject_wrapper(client: FlaskClient) -> None:
    """Cert-Info header without Subject= wrapper returns 403."""
    response = client.get("/validate", headers={"X-Forwarded-Tls-Client-Cert-Info": "CN=Test,O=Org,C=US"})
    assert response.status_code == 403


def test_validate_info_header_second_dn(client: FlaskClient) -> None:
    """Second allowed DN also returns 200."""
    encoded = quote_plus('Subject="CN=CertB,OU=Dept X,O=Company Y,C=ZZ"')
    response = client.get("/validate", headers={"X-Forwarded-Tls-Client-Cert-Info": encoded})
    assert response.status_code == 200
    assert response.data == b"OK"
