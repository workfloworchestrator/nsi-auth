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

"""Functional tests for the Envoy XFCC codecs (``xfcc-cert`` and ``xfcc-subject``)."""

from urllib.parse import quote

from flask.testing import FlaskClient

from tests.functional.test_pem import GOOD_CA_DN, GOOD_CA_PEM

# An XFCC header carries semicolon-separated fields; Cert= is a URL-encoded PEM.
_XFCC_PREFIX = "By=spiffe://cluster.local/ns/default/sa/client;Hash=0123abc"


# ---------------------------------------------------------------------------
# xfcc-cert: parse the full certificate from the Cert= field
# ---------------------------------------------------------------------------


def test_validate_xfcc_cert(xfcc_cert_client: FlaskClient) -> None:
    """XFCC with a Cert= field whose subject is allow-listed returns 200 OK."""
    value = f'{_XFCC_PREFIX};Cert="{quote(GOOD_CA_PEM)}"'
    response = xfcc_cert_client.get("/validate", headers={"x-forwarded-client-cert": value})
    assert response.status_code == 200
    assert response.headers["X-Auth-Method"] == "mTLS"
    assert GOOD_CA_DN in response.headers["X-Client-DN"]


def test_validate_xfcc_cert_no_fallback_to_subject(xfcc_cert_client: FlaskClient) -> None:
    """xfcc-cert must NOT silently fall back to Subject= when Cert= is absent.

    Models the operator error: cert verification intended, but Envoy was not
    configured to emit Cert=. Must fail closed (403), not verify off Subject=.
    """
    value = f'{_XFCC_PREFIX};Subject="{GOOD_CA_DN}"'
    response = xfcc_cert_client.get("/validate", headers={"x-forwarded-client-cert": value})
    assert response.status_code == 403


def test_validate_xfcc_cert_garbage(xfcc_cert_client: FlaskClient) -> None:
    """A Cert= field with non-PEM content returns 403."""
    value = f'{_XFCC_PREFIX};Cert="{quote("not-a-cert")}"'
    response = xfcc_cert_client.get("/validate", headers={"x-forwarded-client-cert": value})
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# xfcc-subject: parse the DN string from the Subject= field
# ---------------------------------------------------------------------------


def test_validate_xfcc_subject(xfcc_subject_client: FlaskClient) -> None:
    """XFCC with an allow-listed Subject= DN returns 200 OK."""
    value = f'{_XFCC_PREFIX};Subject="CN=Test,O=Org,C=US";URI=spiffe://test'
    response = xfcc_subject_client.get("/validate", headers={"x-forwarded-client-cert": value})
    assert response.status_code == 200
    assert response.headers["X-Client-DN"] == "CN=Test,O=Org,C=US"


def test_validate_xfcc_subject_no_fallback_to_cert(xfcc_subject_client: FlaskClient) -> None:
    """xfcc-subject must NOT fall back to Cert= when Subject= is absent."""
    value = f'{_XFCC_PREFIX};Cert="{quote(GOOD_CA_PEM)}"'
    response = xfcc_subject_client.get("/validate", headers={"x-forwarded-client-cert": value})
    assert response.status_code == 403


def test_validate_xfcc_subject_not_in_allowlist(xfcc_subject_client: FlaskClient) -> None:
    """A Subject= DN that is not allow-listed returns 403."""
    value = f'{_XFCC_PREFIX};Subject="CN=Someone Else,O=Unknown,C=NL"'
    response = xfcc_subject_client.get("/validate", headers={"x-forwarded-client-cert": value})
    assert response.status_code == 403
