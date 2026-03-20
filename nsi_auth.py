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
#
"""Verify DN from HTTP header against list of allowed DN's."""
import threading
from logging.config import dictConfig
from typing import Callable

from flask import Flask, request
from pydantic import BaseModel, FilePath
from pydantic_settings import BaseSettings
from watchdog.events import FileModifiedEvent, FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer
from cryptography import x509
import rfc4514_cmp

#
# Authorization application
#
class Settings(BaseSettings):
    """Application settings."""

    # ASSUME: DNs in this file are not necessarily in a X.509 DN normal form, so we'll parse
    # flexibly. File MUST be in UTF-8 encoding, following RFC4514.
    allowed_client_subject_dn_path: FilePath = FilePath("/config/allowed_client_dn.txt")

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
    tls_client_subject_dn_header: str = "ssl-client-subject-dn"

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
    tls_client_cert_header: str = "X-Forwarded-Tls-Client-Cert"

    # Do we look at DN or at FullCert for client authentication?
    tls_use_cert_header: bool = True

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

@app.route("/validate", methods=["GET"])
def validate() -> tuple[str, int]:
    """Verify the DN from the packet header against the list of allowed DN."""
    # https://werkzeug.palletsprojects.com/en/stable/datastructures/#werkzeug.datastructures.Headers
    # .get() returns str

    if settings.tls_use_cert_header:
        # Get DN from PEM certificate
        if not (request_cert_str := request.headers.get(settings.tls_client_cert_header)):
            app.logger.warning(f"no {settings.tls_client_cert_header} header on HTTP request")
            return "Forbidden", 403

        # If Traefik this is in PEM with some changes, see above
        if ',' in request_cert_str:
            app.logger.warning(f"multiple certificates in {settings.tls_client_cert_header} header on HTTP request, unsupported")
            return "Forbidden", 403
        try:
            request_rfc4514_name = rfc4514_cmp.subject_dn_from_traefik_cert_pem(request_cert_str)
        except ValueError:
            app.logger.warning(f"Not a properly encoded certificate in {settings.tls_client_cert_header} header in HTTP request")
            return "Forbidden", 403
    else:
        # DN is ASSUMEd to be sanitized as it comes from NGINX as RFC2253 DN...
        if not (request_dn := request.headers.get(settings.tls_client_subject_dn_header)):
            app.logger.warning(f"no {settings.tls_client_subject_dn_header} header on HTTP request")
            return "Forbidden", 403
        try:
            request_rfc4514_name = rfc4514_cmp.dn_rfc2253_string_to_rfc4514_name(request_dn)
        except ValueError:
            app.logger.warning(f"Not a RFC2253 Distinguished Name {request_dn} header in HTTP request")
            return "Forbidden", 403


    # *** Main authentication line ***
    # x509.Name object equals method does comparison
    for allowed_dn_name in state.allowed_client_subject_dn_names:

        if request_rfc4514_name == allowed_dn_name:
            app.logger.info(f"allow {request_rfc4514_name}")
            return "OK", 200

    app.logger.info(f"deny {request_rfc4514_name}")
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
