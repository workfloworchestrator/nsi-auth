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
# - Support other HTTP proxies than NGINX + Traefik, most can send full cert.
# - Test karl + CANARIE wildcard
#
"""Verify DN from HTTP header against list of allowed DN's."""

import threading
from logging.config import dictConfig
from typing import Callable
from cryptography import x509
from flask import Flask, request
from pydantic import BaseModel, FilePath
from pydantic_settings import BaseSettings
from watchdog.events import FileModifiedEvent, FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

import rfc4514_cmp

# Client TLS certificate Subject DistinguishedName as HTTPS Header:
# -----------------------------------------------------------------
# Kubernetes ingress NGINX's annotation: https://github.com/kubernetes/ingress-nginx/blob/main/docs/user-guide/nginx-configuration/annotations.md
# defined as 'The subject information of the client certificate. Example: "CN=My Client"'
# If we ASSUME this is the $ssl_client_s_dn variable from ngx_http_ssl_module then this is
# defined as (https://nginx.org/en/docs/http/ngx_http_ssl_module.html):
# '$ssl_client_s_dn' returns the “subject DN” string of the client certificate for an
#  established SSL connection according to RFC 2253 (1.11.6);'
# So RFC2253 format. Note that itself is obsoleted by RFC4514, so NGINX has work to do.
#
K8S_NGINX_TLS_CLIENT_SUBJECT_DN_HEADER = "ssl-client-subject-dn"

# Full Client TLS certificate as HTTPS Header:
# --------------------------------------------
# For Traefik:
# * https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/passtlsclientcert/
# * ``that contains the pem.''
# * https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/passtlsclientcert/#pem
# * ``The delimiters and \n will be removed.
# * If there are more than one certificate, they are separated by a ",".''
# * More elaborate:
# * https://doc.traefik.io/traefik/v2.1/middlewares/passtlsclientcert/
# * ``In the example, it is the part between -----BEGIN CERTIFICATE----- and -----END CERTIFICATE----- delimiters :''
#
# * k8s ingress Traefik uses this header, see https://doc.traefik.io/traefik/v1.7/configuration/backends/kubernetes/#general-annotations
# ARNOTODO: find out if Traefik will send multiple certs if a chain is presented, see e.g.
# Internet2's example PEM cert (or is that some form of key chain / key store)

K8S_TRAEFIK_TLS_CLIENT_CERT_HEADER = "X-Forwarded-Tls-Client-Cert"

# Traefik can also send the subject info from the cert:
# * https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/passtlsclientcert/
# * ``X-Forwarded-Tls-Client-Cert-Info header value is a string that has been escaped in order to be a valid URL query.''
# NOTE: Traefik adminstrator must select which fields are put in this Info field! Unclear
# what format (RFC2253/RFC4514_ is used...
#
K8S_TRAEFIK_TLS_CLIENT_SUBJECT_DN_HEADER = "X-Forwarded-Tls-Client-Cert-Info"


#
# Authorization application
#
class Settings(BaseSettings):
    """Application settings."""

    # ASSUME: DNs in this file are not necessarily in a X.509 DN normal form, so we'll parse
    # flexibly. File MUST be in UTF-8 encoding, following RFC4514.
    allowed_client_subject_dn_path: FilePath = FilePath("/config/allowed_client_dn.txt")

    # This setting determines behaviour, one of K8S*_HEADER, see above.
    # If a cert header, then we check using full cert, otherwise passed subject DN.
    tls_client_subject_authn_header: str = K8S_NGINX_TLS_CLIENT_SUBJECT_DN_HEADER

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



# Arno: pydantic cannot handle x509.Name
def get_client_dn(): ### -> tuple[str | None, str]:
    """Extract client DN from request headers, based on settings.tls_client_subject_authn_header

    Returns:
        Tuple of (x509.Name, source) where source indicates which header was used.
    """
    try:
        # https://werkzeug.palletsprojects.com/en/stable/datastructures/#werkzeug.datastructures.Headers
        # .get() returns str

        # Risk: if ingress does DN header, and malicous actor sends cert header, and the
        # proxy does not strip it, we would trust the cert header. So check only the
        # header from settings.
        #
        authn_header_val = request.headers.get(settings.tls_client_subject_authn_header)
        if not authn_header_val:
            return None, "missing"

        if settings.tls_client_subject_authn_header == K8S_TRAEFIK_TLS_CLIENT_CERT_HEADER:
            if ',' in authn_header_val:
                # Traefik sent a chain of certs, separated by , see above
                try:
                    pem_str_list = [v.strip() for v in authn_header_val.split(',') if v.strip()] if authn_header_val else []
                    # Undocumented: assume client cert is first in list
                    # This issue says client cert comes first: https://github.com/keycloak/keycloak/issues/46395#issuecomment-3915177071
                    # Code suggest extra certs follow client cert: https://github.com/tdiesler/keycloak/commit/8d318c552a2c778b65265f4c46a3b30c7dc99a27#diff-4a1b33f7b0a6b8526caf3186df5ccd193f7efcb683dcff9e515de2765ec9fd19R236
                    # "Traefik sends the client certificate and any intermediate CA certificates as PEM blocks in a single `X-Forwarded-Tls-Client-Cert` header, separated by commas."
                    #  --- https://github.com/tdiesler/keycloak/commit/8d318c552a2c778b65265f4c46a3b30c7dc99a27#diff-4a1b33f7b0a6b8526caf3186df5ccd193f7efcb683dcff9e515de2765ec9fd19R288
                    # If Traefik this is in PEM with some changes, see above
                    pem_str = pem_str_list[0]
                except:
                    app.logger.warning(
                        f"multiple certificates in {K8S_TRAEFIK_TLS_CLIENT_CERT_HEADER} header on HTTP request, could not parse")
                    return None, "traefik-pem-multiple-certificates, bad parse"
            else:
                # If Traefik this is in PEM with some changes, see above
                pem_str = authn_header_val

            dn = rfc4514_cmp.subject_dn_from_traefik_cert_pem(pem_str)
            if dn:
                return dn, "traefik-pem"

        elif settings.tls_client_subject_authn_header == K8S_TRAEFIK_TLS_CLIENT_SUBJECT_DN_HEADER:
            dn = rfc4514_cmp.subject_dn_from_traefik_cert_info(authn_header_val)
            if dn:
                return dn, "traefik-info"

        elif settings.tls_client_subject_authn_header == K8S_NGINX_TLS_CLIENT_SUBJECT_DN_HEADER:
            # DN is ASSUMEd to be sanitized as it comes from NGINX as RFC2253 DN...
            dn = rfc4514_cmp.dn_rfc2253_string_to_rfc4514_name(authn_header_val)
            if dn:
                return dn, "nginx"
        else:
            # Default no name, higher layer logs and sends 403.
            return None, "none"

    except ValueError as e:
            return None, str(e)


@app.route("/validate", methods=["GET"])
def validate() -> tuple[str, int]:
    """Verify the DN from the packet header against the list of allowed DN."""
    request_rfc4514_name, source = get_client_dn()

    if request_rfc4514_name is None:
        app.logger.warning(
            f"Missing authorization header or incorrect value: {settings.tls_client_subject_authn_header}: {source}"
        )
        return "Forbidden", 403

    # *** Main authentication line ***
    # x509.Name object equals method does comparison
    for allowed_dn_name in state.allowed_client_subject_dn_names:

        if request_rfc4514_name == allowed_dn_name:
            app.logger.info(f"allow {request_rfc4514_name} (from {source} header)")
            return "OK", 200

    app.logger.info(f"deny {request_rfc4514_name} (from {source} header)")
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
    new_allowed_client_subject_dn_names = []
    try:
        with filepath.open("r") as f:
            lines = [line.strip() for line in f if line.strip()]
    except Exception as e:
        app.logger.error(f"cannot load allowed client DN from {filepath}: {e!s}")
    else:
        # Convert DNs from "free" file format into RFC4514 format for comparison against k8s ingress
        # NGINX's "ssl-client-subject-dn" annotation header (also converted to RFC4514 format)
        for line in lines:
            try:
                rfc4514_name = rfc4514_cmp.dn_tagvalue_string_to_rfc4514_name(line)
            except ValueError:
                app.logger.warning(f"Not a Distinguished Name {line} header in {filepath}")
            else:
                new_allowed_client_subject_dn_names.append(rfc4514_name)

        # Detect change in persistent state vs run-time
        if state.allowed_client_subject_dn_names != new_allowed_client_subject_dn_names:
            state.allowed_client_subject_dn_names = new_allowed_client_subject_dn_names
            app.logger.info(f"load {len(new_allowed_client_subject_dn_names)} DN from {filepath}")

if settings.use_watchdog:
    watchdog_file(settings.allowed_client_subject_dn_path, load_allowed_client_dn)
else:
    watch_file(settings.allowed_client_subject_dn_path, load_allowed_client_dn)
