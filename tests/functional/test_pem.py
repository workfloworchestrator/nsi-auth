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

"""Functional tests for the generic standard-PEM (``pem``) codec under any header name."""

from urllib.parse import quote

import pytest
from flask.testing import FlaskClient

# Standard PEM (delimiters + newlines intact) — Subject: CN=Good CA,O=Test Certificates 2011,C=US.
# Same trust-anchor certificate used by the Traefik PEM tests; here it is a real PEM, not minimized.
GOOD_CA_PEM = """-----BEGIN CERTIFICATE-----
MIIDfDCCAmSgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf
MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg
QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowQDELMAkGA1UE
BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExEDAOBgNVBAMT
B0dvb2QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCQWJpHYo37
Xfb7oJSPe+WvfTlzIG21WQ7MyMbGtK/m8mejCzR6c+f/pJhEH/OcDSMsXq8h5kXa
BGqWK+vSwD/Pzp5OYGptXmGPcthDtAwlrafkGOS4GqIJ8+k9XGKs+vQUXJKsOk47
RuzD6PZupq4s16xaLVqYbUC26UcY08GpnoLNHJZS/EmXw1ZZ3d4YZjNlpIpWFNHn
UGmdiGKXUPX/9H0fVjIAaQwjnGAbpgyCumWgzIwPpX+ElFOUr3z7BoVnFKhIXze+
VmQGSWxZxvWDUN90Ul0tLEpLgk3OVxUB4VUGuf15OJOpgo1xibINPmWt14Vda2N9
yrNKloJGZNqLAgMBAAGjfDB6MB8GA1UdIwQYMBaAFOR9X9FclYYILAWuvnW2ZafZ
XahmMB0GA1UdDgQWBBRYAYQkG7wrUpRKPaUQchRR9a86yTAOBgNVHQ8BAf8EBAMC
AQYwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA8GA1UdEwEB/wQFMAMBAf8wDQYJ
KoZIhvcNAQELBQADggEBADWHlxbmdTXNwBL/llwhQqwnazK7CC2WsXBBqgNPWj7m
tvQ+aLG8/50Qc2Sun7o2VnwF9D18UUe8Gj3uPUYH+oSI1vDdyKcjmMbKRU4rk0eo
3UHNDXwqIVc9CQS9smyV+x1HCwL4TTrq+LXLKx/qVij0Yqk+UJfAtrg2jnYKXsCu
FMBQQnWCGrwa1g1TphRp/RmYHnMynYFmZrXtzFz+U9XEA7C+gPq4kqDI/iVfIT1s
6lBtdB50lrDVwl2oYfAvW/6sC2se2QleZidUmrziVNP4oEeXINokU6T6p//HM1FG
QYw2jOvpKcKtWCSAnegEbgsGYzATKjmPJPJ0npHFqzM=
-----END CERTIFICATE-----"""

GOOD_CA_DN = "CN=Good CA,O=Test Certificates 2011,C=US"


def test_validate_with_standard_pem(pem_client: FlaskClient) -> None:
    """A URL-encoded standard PEM whose subject is allow-listed returns 200 OK.

    HTTP headers cannot contain newlines, so the PEM is URL-encoded on the wire
    (as nginx's $ssl_client_escaped_cert does); the pem codec URL-decodes it.
    """
    response = pem_client.get("/validate", headers={"ssl-client-cert": quote(GOOD_CA_PEM)})
    assert response.status_code == 200
    assert response.data == b"OK"
    assert response.headers["X-Auth-Method"] == "mTLS"
    assert GOOD_CA_DN in response.headers["X-Client-DN"]


def test_validate_pem_missing_header(pem_client: FlaskClient) -> None:
    """Missing header returns 403 without auth headers."""
    response = pem_client.get("/validate")
    assert response.status_code == 403
    assert "X-Client-DN" not in response.headers


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("not-a-cert", id="garbage"),
        pytest.param("", id="empty"),
        pytest.param(quote(GOOD_CA_PEM.replace("M", "Z")), id="corrupted-base64"),
    ],
)
def test_validate_pem_bad_input(pem_client: FlaskClient, value: str) -> None:
    """Malformed PEM input returns 403."""
    response = pem_client.get("/validate", headers={"ssl-client-cert": value})
    assert response.status_code == 403
