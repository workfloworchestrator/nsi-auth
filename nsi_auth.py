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
#
# TODO:
# - XFCC Subject= is assumed RFC 2253 (comma-separated); confirm against Envoy's
#   actual serialization, or prefer the xfcc-cert codec which parses the full cert.
# - Test CANARIE wildcard
#
"""Verify DN from HTTP header against list of allowed DN's."""

import logging
import platform
import threading
from enum import Enum
from importlib.metadata import version
from typing import Callable

import structlog
from cryptography import x509
from flask import Flask, request
from pydantic import BaseModel, FilePath
from pydantic_settings import BaseSettings
from watchdog.events import FileModifiedEvent, FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

import rfc4514_cmp

logger = structlog.get_logger(__name__)

# The client identity is read from one HTTP header (name configurable via
# TLS_CLIENT_SUBJECT_AUTHN_HEADER) and parsed with an explicit codec
# (TLS_CLIENT_AUTHN_FORMAT). Header name and codec are independent, so any
# proxy/header combination works. Common proxy headers and their codec:
#
# * ingress-nginx  ssl-client-subject-dn            -> dn-rfc2253   (RFC 2253 DN)
# * Envoy (Lua)    ssl-client-subject-dn            -> dn-rfc2253   (subjectPeerCertificate())
# * Traefik        X-Forwarded-Tls-Client-Cert      -> traefik-pem  (minimized PEM chain)
# * Traefik        X-Forwarded-Tls-Client-Cert-Info -> traefik-info (Subject="...")
# * any proxy      <any name>                       -> pem          (standard PEM cert)
# * Envoy (XFCC)   x-forwarded-client-cert          -> xfcc-cert / xfcc-subject
#
# nginx ssl-client-subject-dn is RFC 2253 per ngx_http_ssl_module. Traefik's
# PassTLSClientCert (pem: true) strips PEM delimiters/newlines and comma-separates
# a chain. Envoy XFCC fields are documented at the HTTP connection manager headers
# reference (set_current_client_cert_details controls which fields are present).


class ClientAuthnFormat(str, Enum):
    """How to parse the configured client-identity header into a Subject DN."""

    DN_RFC2253 = "dn-rfc2253"      # bare RFC 2253 DN string (ingress-nginx, Envoy Lua)
    TRAEFIK_INFO = "traefik-info"  # Traefik X-Forwarded-Tls-Client-Cert-Info: Subject="..."
    TRAEFIK_PEM = "traefik-pem"    # Traefik X-Forwarded-Tls-Client-Cert: minimized PEM chain
    PEM = "pem"                    # standard PEM certificate
    XFCC_CERT = "xfcc-cert"        # Envoy XFCC Cert= field (URL-encoded PEM)
    XFCC_SUBJECT = "xfcc-subject"  # Envoy XFCC Subject= field (DN string)


DEFAULT_AUTHN_HEADER = "ssl-client-subject-dn"


#
# Authorization application
#
class Settings(BaseSettings):
    """Application settings."""

    # ASSUME: DNs in this file are not necessarily in a X.509 DN normal form, so we'll parse
    # flexibly. File MUST be in UTF-8 encoding, following RFC4514.
    allowed_client_subject_dn_path: FilePath = FilePath("/config/allowed_client_dn.txt")

    # Name of the HTTP header carrying the client identity (any header name).
    tls_client_subject_authn_header: str = DEFAULT_AUTHN_HEADER

    # How to parse that header's value into a Subject DN (see ClientAuthnFormat).
    tls_client_authn_format: ClientAuthnFormat = ClientAuthnFormat.DN_RFC2253

    use_watchdog: bool = False
    log_level: str = "INFO"


# State cannot inherit from BaseModel, as x509.name.Name does not play nice with PyDantic
# Alternative is a DataClass, or no parent. Latter chosen.
class State:
    """Application state."""
    # Note: if we inherit from BaseModel we get "Unable to generate pydantic-core
    # schema for <class 'cryptography.x509.name.Name'>."
    # So we do not inherit ;o)
    allowed_client_subject_dn_names: list[x509.name.Name] = []
    # Precomputed canonical attrs for each allowed DN. Used for order-independent
    # equality in validate() — x509.Name.__eq__ is RDN-order-sensitive, but our
    # allowlist semantics are not.
    allowed_client_subject_dn_attrs: set[frozenset[tuple[str, str]]] = set()


def configure_logging() -> None:
    """Configure structlog and the stdlib root logger to share a single output pipeline.

    Both structlog-native loggers and foreign stdlib loggers (e.g. uvicorn) are
    routed through a structlog ``ProcessorFormatter``, ensuring consistent
    formatting across all log sources.
    """
    numeric_level = getattr(logging, settings.log_level.upper(), logging.INFO)

    shared_processors: list[structlog.types.Processor] = [
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]

    structlog.configure(
        processors=shared_processors
        + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(numeric_level),
        logger_factory=structlog.stdlib.LoggerFactory(),
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.dev.ConsoleRenderer(),
        ],
        foreign_pre_chain=shared_processors,
    )

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(numeric_level)

    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uvi_logger = logging.getLogger(name)
        uvi_logger.handlers.clear()
        uvi_logger.propagate = True

    class _SuppressHealthCheck(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            return " /health " not in record.getMessage()

    access_logger = logging.getLogger("uvicorn.access")
    access_logger.filters.clear()
    access_logger.addFilter(_SuppressHealthCheck())


def init_app() -> Flask:
    """Initialize Flask app."""
    configure_logging()
    return Flask(__name__)


settings = Settings()
state = State()
app = init_app()
logger.info(
    "Starting NSI Auth %s using Python %s (%s) on %s",
    version("nsi_auth"),
    platform.python_version(),
    platform.python_implementation(),
    platform.node(),
    **settings.model_dump(mode="json"),
)



# Codec registry: each format maps to a parser turning the header value into an
# x509.Name (or None when the configured source is absent). Adding support for a
# new proxy is one new entry here plus its parser in rfc4514_cmp.
_CODECS = {
    ClientAuthnFormat.DN_RFC2253: rfc4514_cmp.dn_rfc2253_string_to_rfc4514_name,
    ClientAuthnFormat.TRAEFIK_INFO: rfc4514_cmp.subject_dn_from_traefik_cert_info,
    ClientAuthnFormat.TRAEFIK_PEM: rfc4514_cmp.subject_dn_from_traefik_cert_pem,
    ClientAuthnFormat.PEM: rfc4514_cmp.subject_dn_from_pem_header,
    ClientAuthnFormat.XFCC_CERT: rfc4514_cmp.subject_dn_from_xfcc_cert,
    ClientAuthnFormat.XFCC_SUBJECT: rfc4514_cmp.subject_dn_from_xfcc_subject,
}


# Arno: pydantic cannot handle x509.Name
def get_client_dn():  ### -> tuple[x509.Name | None, str]:
    """Extract the client Subject DN from the configured header and format.

    The header name (``settings.tls_client_subject_authn_header``) and the parse
    codec (``settings.tls_client_authn_format``) are independent settings, so any
    proxy / header combination can be configured. Returns ``(x509.Name, source)``
    on success or ``(None, reason)`` on failure. There is no fallback between
    codecs: a misconfigured source fails closed rather than silently using a
    different field.

    Security: only the configured header is read, so a client that also sends a
    different identity header cannot influence the result.
    """
    raw = request.headers.get(settings.tls_client_subject_authn_header)
    if not raw:
        return None, "missing"

    fmt = settings.tls_client_authn_format
    try:
        return _CODECS[fmt](raw), fmt.value
    except ValueError as e:
        return None, str(e)


@app.route("/health", methods=["GET"])
def health() -> tuple[str, int]:
    """Health check endpoint for k8s liveness/readiness probes."""
    return "OK", 200


# Accept any method: Envoy ext_authz mirrors the downstream request method onto
# the /validate subrequest (POST for SOAP backends like safnari/pce, GET for dds).
# Validation is header-only, so the method is irrelevant; restricting to GET 405s
# every POST-based backend. (nginx/Traefik forward-auth always GET, so GET-only
# worked there.)
@app.route("/validate", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
def validate() -> tuple[str, int] | tuple[str, int, dict[str, str]]:
    """Verify the DN from the packet header against the list of allowed DN."""
    logger.debug("validate request headers", **dict(request.headers))
    request_rfc4514_name, source = get_client_dn()

    if request_rfc4514_name is None:
        logger.warning(
            f"Missing authorization header or incorrect value: {settings.tls_client_subject_authn_header}: {source}"
        )
        return "Forbidden", 403

    # Order-independent comparison: same multiset of (OID, value) pairs.
    # x509.Name.__eq__ is RDN-order-sensitive, which breaks when different
    # proxies/serializers emit the same identity in different orders (e.g.
    # Go's cert.Subject.String() vs. OpenSSL's RFC 2253 output).
    if rfc4514_cmp.name_attrs(request_rfc4514_name) in state.allowed_client_subject_dn_attrs:
        logger.info(f"allow {request_rfc4514_name} (from {source} header)")
        return "OK", 200, {
            "X-Auth-Method": "mTLS",
            "X-Client-DN": rfc4514_cmp.name_rfc4514_string(request_rfc4514_name),
        }

    logger.info(f"deny {request_rfc4514_name} (from {source} header)")
    return "Forbidden", 403

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
        logger.info(f"watch {self.filepath} for changes")

    def on_modified(self, event: FileSystemEvent) -> None:
        """Call load_allowed_client_dn() when `filepath` is modified."""
        logger.debug(f"on_modified {event} {FilePath(str(event.src_path)).resolve()} {self.filepath.resolve()}")
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
        logger.info(f"watch {filepath} for changes")
        while True:
            logger.debug(f"check modification time of {filepath}")
            try:
                modified = filepath.stat().st_mtime_ns
            except FileNotFoundError as e:
                logger.error(f"cannot get last modification time of {filepath}: {e!s}")
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
def _parse_allowlist_entry(line: str, filepath: FilePath) -> x509.name.Name | None:
    """Parse one allowlist line; log and return None on failure."""
    try:
        return rfc4514_cmp.dn_tagvalue_string_to_rfc4514_name(line)
    except ValueError:
        logger.warning(f"Not a Distinguished Name {line} header in {filepath}")
        return None


def load_allowed_client_dn(filepath: FilePath) -> None:
    """Load list of allowed client DN from file."""
    try:
        with filepath.open("r") as f:
            lines = [line.strip() for line in f if line.strip()]
    except Exception as e:
        logger.error(f"cannot load allowed client DN from {filepath}: {e!s}")
        return

    parsed = [_parse_allowlist_entry(line, filepath) for line in lines]
    new_names = [name for name in parsed if name is not None]
    new_attrs = {rfc4514_cmp.name_attrs(name) for name in new_names}

    # Detect change in persistent state vs run-time
    if state.allowed_client_subject_dn_names != new_names:
        state.allowed_client_subject_dn_names = new_names
        state.allowed_client_subject_dn_attrs = new_attrs
        logger.info(f"load {len(new_names)} DN from {filepath}")

if settings.use_watchdog:
    watchdog_file(settings.allowed_client_subject_dn_path, load_allowed_client_dn)
else:
    watch_file(settings.allowed_client_subject_dn_path, load_allowed_client_dn)
