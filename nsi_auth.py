#  Copyright 2025 SURF.
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
"""Verify DN from HTTP header against list of allowed DN's."""

import base64
import re
import threading
from logging.config import dictConfig
from typing import Callable
from urllib.parse import unquote, unquote_plus

from cryptography import x509
from cryptography.x509.oid import NameOID
from flask import Flask, request
from pydantic import BaseModel, FilePath
from pydantic_settings import BaseSettings
from watchdog.events import FileModifiedEvent, FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

# OID not included in cryptography.x509.oid.NameOID
OID_ORGANIZATION_IDENTIFIER = x509.ObjectIdentifier("2.5.4.97")

_OID_SHORT_NAMES = {
    NameOID.COUNTRY_NAME: "C",
    NameOID.STATE_OR_PROVINCE_NAME: "ST",
    NameOID.LOCALITY_NAME: "L",
    NameOID.ORGANIZATION_NAME: "O",
    NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
    NameOID.COMMON_NAME: "CN",
    NameOID.SERIAL_NUMBER: "serialNumber",
    NameOID.EMAIL_ADDRESS: "emailAddress",
    OID_ORGANIZATION_IDENTIFIER: "organizationIdentifier",
}


#
# Authorization application
#
class Settings(BaseSettings):
    """Application settings."""

    allowed_client_subject_dn_path: FilePath = FilePath("/config/allowed_client_dn.txt")
    ssl_client_subject_dn_header: str = "ssl-client-subject-dn"
    use_watchdog: bool = False
    log_level: str = "INFO"


class State(BaseModel):
    """Application state."""

    allowed_client_subject_dn: list[str] = []


def init_app() -> Flask:
    """Initialize Flask app."""
    dictConfig(
        {
            "version": 1,
            "formatters": {
                "default": {
                    "format": "[%(asctime)s] [%(module)s] [%(levelname)s] %(message)s",
                }
            },
            "handlers": {
                "wsgi": {
                    "class": "logging.StreamHandler",
                    "stream": "ext://flask.logging.wsgi_errors_stream",
                    "formatter": "default",
                }
            },
            "root": {"level": "INFO", "handlers": ["wsgi"]},
            "disable_existing_loggers": False,
        }
    )
    app = Flask(__name__)
    app.logger.setLevel(settings.log_level)

    return app


settings = Settings()
state = State()
app = init_app()


def _escape_dn_value(value: str) -> str:
    """Escape special characters in a DN attribute value per RFC 4514."""
    value = value.replace("\\", "\\\\")
    for ch in (",", "+", '"', "<", ">", ";"):
        value = value.replace(ch, f"\\{ch}")
    if value.startswith("#"):
        value = "\\" + value
    if value.startswith(" "):
        value = "\\ " + value[1:]
    if value.endswith(" "):
        value = value[:-1] + "\\ "
    return value


def extract_dn_from_pem_header(header_value: str) -> str | None:
    """Extract DN from Traefik's X-Forwarded-Tls-Client-Cert header (URL-encoded PEM).

    Parses the full certificate to access all subject fields including
    organizationIdentifier (OID 2.5.4.97) and emailAddress (OID 1.2.840.113549.1.9.1).
    Returns a normalized DN string in DER field order, or None on parse failure.
    """
    try:
        # Traefik strips newlines from the PEM before URL-encoding (to prevent header injection),
        # so load_pem_x509_certificate would fail on the re-assembled string. Instead, extract
        # the base64 between the PEM markers and load as DER.
        # Use unquote (not unquote_plus) to preserve '+' characters valid in base64.
        pem_str = unquote(header_value)
        b64 = re.sub(r"-----[^-]+-----", "", pem_str).replace(" ", "")
        cert = x509.load_der_x509_certificate(base64.b64decode(b64))
    except Exception as e:
        app.logger.warning(f"failed to parse PEM from X-Forwarded-Tls-Client-Cert: {e!s}")
        return None

    parts = [
        f"{_OID_SHORT_NAMES.get(attr.oid, attr.oid.dotted_string)}={_escape_dn_value(attr.value)}"
        for attr in cert.subject
    ]
    return ",".join(parts)


def extract_dn_from_traefik_header(header_value: str) -> str | None:
    """Extract DN from Traefik's X-Forwarded-Tls-Client-Cert-Info header.

    Traefik format: Subject="CN=...,O=...,C=..."
    Returns the DN string without the Subject="" wrapper, or None if not found.
    """
    # Match Subject="..." pattern and extract the DN
    # Traefik URL-encodes the header value, so decode it first
    match = re.search(r'Subject="([^"]+)"', unquote_plus(header_value))
    if match:
        return match.group(1)
    return None


def get_client_dn() -> tuple[str | None, str]:
    """Extract client DN from request headers.

    Priority order:
    1. X-Forwarded-Tls-Client-Cert (Traefik PEM - all subject fields)
    2. X-Forwarded-Tls-Client-Cert-Info (Traefik Info - limited fields)
    3. ssl-client-subject-dn or configured header (nginx fallback)

    Returns:
        Tuple of (dn, source) where source indicates which header was used.
    """
    pem_header = request.headers.get("X-Forwarded-Tls-Client-Cert")
    if pem_header:
        dn = extract_dn_from_pem_header(pem_header)
        if dn:
            return dn, "traefik-pem"

    traefik_header = request.headers.get("X-Forwarded-Tls-Client-Cert-Info")
    if traefik_header:
        dn = extract_dn_from_traefik_header(traefik_header)
        if dn:
            return dn, "traefik"

    nginx_header = request.headers.get(settings.ssl_client_subject_dn_header)
    if nginx_header:
        return nginx_header, "nginx"

    return None, "none"


@app.route("/validate", methods=["GET"])
def validate() -> tuple[str, int]:
    """Verify the DN from the packet header against the list of allowed DN."""
    dn, source = get_client_dn()

    if not dn:
        app.logger.warning(
            f"no client DN found in headers (tried X-Forwarded-Tls-Client-Cert, "
            f"X-Forwarded-Tls-Client-Cert-Info, {settings.ssl_client_subject_dn_header})"
        )
        return "Forbidden", 403

    if dn not in state.allowed_client_subject_dn:
        app.logger.info(f"deny {dn} (from {source} header)")
        return "Forbidden", 403

    app.logger.info(f"allow {dn} (from {source} header)")
    return "OK", 200


#
# File watch based on watchdog.
#
class FileChangeHandler(FileSystemEventHandler):
    """On filesystem event, call load_allowed_client_dn() when `filepath` is modified."""

    def __init__(self, filepath: FilePath, callback: Callable[[FilePath], None]) -> None:
        """Set the filepath of the file to watch."""
        self.filepath = filepath
        self.callback = callback
        load_allowed_client_dn(self.filepath)
        app.logger.info(f"watch {self.filepath} for changes")

    def on_modified(self, event: FileSystemEvent) -> None:
        """Call load_allowed_client_dn() when `filepath` is modified."""
        app.logger.debug(f"on_modified {event} {FilePath(str(event.src_path)).resolve()} {self.filepath.resolve()}")
        if FilePath(str(event.src_path)).resolve() == self.filepath.resolve():
            self.callback(self.filepath)


def watchdog_file(filepath: FilePath, callback: Callable[[FilePath], None]) -> None:
    """Setup watchdog to watch directory that the file resides in and call handler on change."""
    observer = Observer()
    observer.schedule(
        FileChangeHandler(filepath, callback),
        path=str(filepath.parent),
        recursive=True,
        event_filter=[FileModifiedEvent],
    )
    observer.start()


#
# File watch based on Path.stat().
#
def watch_file(filepath: FilePath, callback: Callable[[FilePath], None]) -> None:
    """Watch modification time of `filepath` in a thread and call `callback` on change."""

    def watch() -> None:
        """If modification time of `filepath` changes call `callback`."""
        last_modified = 0
        app.logger.info(f"watch {filepath} for changes")
        while True:
            app.logger.debug(f"check modification time of {filepath}")
            try:
                modified = filepath.stat().st_mtime_ns
            except FileNotFoundError as e:
                app.logger.error(f"cannot get last modification time of {filepath}: {e!s}")
            else:
                if last_modified < modified:
                    last_modified = modified
                    callback(filepath)
            event.wait(5)

    event = threading.Event()
    threading.Thread(target=watch, daemon=True).start()


#
# Load DN from file.
#
def load_allowed_client_dn(filepath: FilePath) -> None:
    """Load list of allowed client DN from file."""
    try:
        with filepath.open("r") as f:
            new_allowed_client_subject_dn = [line.strip() for line in f if line.strip()]
    except Exception as e:
        app.logger.error(f"cannot load allowed client DN from {filepath}: {e!s}")
    else:
        if state.allowed_client_subject_dn != new_allowed_client_subject_dn:
            state.allowed_client_subject_dn = new_allowed_client_subject_dn
            app.logger.info(f"load {len(new_allowed_client_subject_dn)} DN from {filepath}")


if settings.use_watchdog:
    watchdog_file(settings.allowed_client_subject_dn_path, load_allowed_client_dn)
else:
    watch_file(settings.allowed_client_subject_dn_path, load_allowed_client_dn)
