# NSI Authentication Server (`nsi-auth`)

[![Helm Chart](https://img.shields.io/badge/Helm%20Chart-available-blue)](https://bandwidthondemand.github.io/nsi-node/)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-compatible-brightgreen)](https://kubernetes.io/)
[![License](https://img.shields.io/badge/License-Apache%202.0-lightgrey.svg)](https://opensource.org/licenses/Apache-2.0)

The **NSI Authentication Server** (`nsi-auth`) is designed to integrate with
Kubernetes ingress controllers such as **ingress-nginx**.

When an authentication request is sent to `nsi-auth`, the server verifies
whether the certificate’s **Distinguished Name (DN)**, provided in an HTTP
header, is included in the list of allowed DNs.

- ✅ If the DN is authorized, the server responds with **HTTP 200 (OK)**  
- ❌ If not authorized, it returns **HTTP 403 (Forbidden)**

---

## 📘 Table of Contents

- [Overview](#nsi-authentication-server-nsi-auth)
- [Installation and Configuration](#installation-and-configuration)
  - [1. Deploying `nsi-auth`](#1-deploying-nsi-auth)
  - [2. CA Certificate Handling](#2-ca-certificate-handling)
  - [3. Configuration Options](#3-configuration-options)
  - [4. Ingress Configuration](#4-ingress-configuration)
- [Summary](#summary)

---

## Installation and Configuration

### 1. Deploying `nsi-auth`

`nsi-auth` is deployed via a Helm chart. The full list of configuration options
can be found in [`chart/values.yaml`](chart/values.yaml).

Below is an example configuration snippet:

```yaml
image:
  repository: ghcr.io/bandwidthondemand/nsi-auth
  pullPolicy: IfNotPresent
  tag: "latest"

service:
  type: ClusterIP
  port: 80
  targetPort: 8000

volumes:
  - name: config
    configMap:
      name: nsi-auth-config
      optional: false

volumeMounts:
  - name: config
    mountPath: "/config"
    readOnly: true

env:
  ALLOWED_CLIENT_SUBJECT_DN_PATH: "/config/allowed_client_dn.txt"
  SSL_CLIENT_SUBJECT_DN_HEADER: "ssl-client-subject-dn"
  USE_WATCHDOG: "False"
  LOG_LEVEL: "INFO"

config:
  inlineData: |-
    allowed_client_dn.txt: |-
      CN=CertA,OU=Dept X,O=Company 1,C=NL
      CN=CertB,OU=Dept Y,O=Company 2,C=NL
      CN=CertC,OU=Dept Z,O=Company 3,C=NL
  additionalTrustedCA: ""
```
  
You can override default values by passing a custom values file:

```shell
helm upgrade --install --values my-values.yaml nsi-auth chart
```

> **Note:**
>
> The value `configMap.name` is defined as `{{ .Release.Name }}-config` and must match your Helm release name.
> In this example, the release name is nsi-auth.

Alternatively, install directly from the nsi-node Helm repository:

```shell
helm repo add nsi-node https://bandwidthondemand.github.io/nsi-node/
helm repo update
helm upgrade --install --values my-values.yaml nsi-auth nsi-node/nsi-auth
```

### 2. CA Certificate Handling

During installation, a Kubernetes secret named `{{ .Release.Name }}-ca` is
automatically created.  This secret contains a `ca.crt` file, which includes:

- The list of CA certificates maintained by [cURL](https://curl.se/docs/caextract.html)
- Any additional certificates defined under `config.additionalTrustedCA`

This allows you to extend the trusted CA list with other certificates,
including self-signed CAs if needed.

The `ca.crt` secret is then used by the ingress controller to establish the
trusted CA chain (see [Ingress Configuration](#4-ingress-configuration)).

### 3. Configuration Options

| Variable | Description                                                                                                                              | Default |
| -------------------------------- |------------------------------------------------------------------------------------------------------------------------------------------| ------------------------------- |
| `ALLOWED_CLIENT_SUBJECT_DN_PATH` | Path to the file listing allowed client certificate DNs. DNs should be as close to RFC4514 as possible, and stored as UTF-8 in the file. | `/config/allowed_client_dn.txt` |
| `SSL_CLIENT_SUBJECT_DN_HEADER` | HTTP header containing the client certificate DN. For **ingress-nginx**, this should not be changed.                                     | `ssl-client-subject-dn`         |
| `USE_WATCHDOG`                   | Enables file-change monitoring using [watchdog](https://pypi.org/project/watchdog/). Useful for non-Kubernetes environments.             | `False`                         |
| `LOG_LEVEL`                      | Logging verbosity. Options: `DEBUG`, `INFO`, `WARNING`, `ERROR`.                                                                         | `INFO`                          |

**File reload behavior:**

By default, `nsi-auth` uses a simple polling mechanism (every 5 seconds) to
detect changes to the DN file.  If `USE_WATCHDOG` is enabled, the `watchdog`
module provides faster, event-based file monitoring.

> ⚠️ Note:
> `watchdog` cannot be used when running in Kubernetes, because ConfigMap updates replace the file via symbolic
> links, and this is not detected.

### 4. Ingress Configuration

Finally, configure the ingress controller of the application to:

1. Use the `ca.crt` secret created by `nsi-auth`
2. Enable and verify **mutual TLS (mTLS)** authentication
3. Forward the client certificate DN to `nsi-auth` for validation

Assuming `nsi-auth` is deployed in the `production` namespace, use the
following ingress annotations:

```yaml
nginx.ingress.kubernetes.io/auth-tls-secret: production/nsi-auth-ca
nginx.ingress.kubernetes.io/auth-tls-verify-client: "on"
nginx.ingress.kubernetes.io/auth-tls-verify-depth: "3"
nginx.ingress.kubernetes.io/auth-url: http://nsi-auth.production.svc.cluster.local/validate
```

These settings ensure that the ingress controller:

- Validates client certificates against the trusted CA chain
- Delegates authorization to the nsi-auth service

---

📄 License

This project is licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).

---

🧠 See Also

- [Kubernetes Ingress documentation](https://kubernetes.io/docs/concepts/services-networking/ingress/)
- [Nginx Ingress Controller](https://kubernetes.github.io/ingress-nginx/)
- [cURL CA Certificates](https://kubernetes.github.io/ingress-nginx/)
