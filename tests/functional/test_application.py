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
import pytest
from flask.testing import FlaskClient


def test_root_not_found(client: FlaskClient) -> None:
    """Verify that the root endpoint returns 404."""
    response = client.get("/")
    assert response.status_code == 404


def test_validate_without_dn_header(client: FlaskClient) -> None:
    """Verify that the /validate endpoint returns 403 without DN header."""
    response = client.get("/validate")
    assert response.status_code == 403
    assert response.data == b"Forbidden"


def test_validate_with_valid_dn_header(client: FlaskClient) -> None:
    """Verify that the /validate endpoint returns 200 with correct DN header."""
    # According to https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.4
    # Country is "the two-character codes from ISO 3166". ZZ is a user-assigned element :-)
    # https://www.iso.org/obp/ui/#iso:pub:PUB500001:en
    headers = {
        "ssl-client-subject-dn": "CN=CertA,OU=Dept X,O=Company Y,C=ZZ",
    }
    response = client.get("/validate", headers=headers)
    assert response.status_code == 200
    assert response.data == b"OK"


def test_validate_with_second_valid_dn_header(client: FlaskClient) -> None:
    """Verify that the second allowed DN also returns 200."""
    headers = {
        "ssl-client-subject-dn": "CN=CertB,OU=Dept X,O=Company Y,C=Z",
    }
    response = client.get("/validate", headers=headers)
    assert response.status_code == 200
    assert response.data == b"OK"


def test_validate_with_invalid_dn_header(client: FlaskClient) -> None:
    """Verify that the /validate endpoint returns 403 with incorrect DN header."""
    headers = {
        "ssl-client-subject-dn": "CN=CertA,OU=Dept X,O=Company Y,C=ZZZZZZZZZZ",
    }
    response = client.get("/validate", headers=headers)
    assert response.status_code == 403
    assert response.data == b"Forbidden"


def test_validate_with_empty_dn_header(client: FlaskClient) -> None:
    """Verify that an empty DN header returns 403."""
    headers = {
        "ssl-client-subject-dn": "",
    }
    response = client.get("/validate", headers=headers)
    assert response.status_code == 403


@pytest.mark.parametrize("method", ["post", "put", "delete", "patch"])
def test_validate_rejects_non_get_methods(client: FlaskClient, method: str) -> None:
    """Verify that the /validate endpoint only accepts GET requests."""
    response = getattr(client, method)("/validate")
    assert response.status_code == 405
