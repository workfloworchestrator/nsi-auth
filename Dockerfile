# syntax=docker/dockerfile:1@sha256:572cebbc2b15e6f84c077742952674889cb63cd5e9b80abdffcbe587b6f19183
#
# Build stage
FROM ghcr.io/astral-sh/uv:python3.13-alpine@sha256:6e3e7a0061d007bf3d7f1b24c258b62f384ef14fbe2df673493d2b53e88b526b AS build
ARG VERSION
ENV SETUPTOOLS_SCM_PRETEND_VERSION_FOR_NSI_AUTH=${VERSION}
WORKDIR /app
COPY pyproject.toml LICENSE README.md nsi_auth.py rfc4514_cmp.py ./
RUN uv build --no-cache --wheel --out-dir dist

# Final stage
FROM ghcr.io/astral-sh/uv:python3.13-alpine@sha256:6e3e7a0061d007bf3d7f1b24c258b62f384ef14fbe2df673493d2b53e88b526b
# Drops emSign ECC Root CA - G3 (ca-certificates 20261020); remove once the base image has it.
RUN apk upgrade --no-cache ca-certificates ca-certificates-bundle
COPY --from=build /app/dist/*.whl /tmp/
RUN uv pip install --system --no-cache /tmp/*.whl && rm /tmp/*.whl
RUN addgroup -g 1000 nsi_auth && adduser -D -u 1000 -G nsi_auth nsi_auth
USER nsi_auth
WORKDIR /home/nsi_auth
EXPOSE 8000/tcp
CMD ["uvicorn", "--host", "0.0.0.0", "--port", "8000", "--interface", "wsgi", "nsi_auth:app"]
