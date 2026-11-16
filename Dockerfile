# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
#
# Build stage
FROM ghcr.io/astral-sh/uv:python3.13-alpine@sha256:f2d6278d0821c35881b010ddbf75825049661a98dbfdf61bbd1407e8dd544d00 AS build
ARG VERSION
ENV SETUPTOOLS_SCM_PRETEND_VERSION_FOR_NSI_AUTH=${VERSION}
WORKDIR /app
COPY pyproject.toml LICENSE README.md nsi_auth.py rfc4514_cmp.py ./
RUN uv build --no-cache --wheel --out-dir dist

# Final stage
FROM ghcr.io/astral-sh/uv:python3.13-alpine@sha256:f2d6278d0821c35881b010ddbf75825049661a98dbfdf61bbd1407e8dd544d00
# Drops emSign ECC Root CA - G3 (ca-certificates 20261020); remove once the base image has it.
RUN apk upgrade --no-cache ca-certificates ca-certificates-bundle
COPY --from=build /app/dist/*.whl /tmp/
RUN uv pip install --system --no-cache /tmp/*.whl && rm /tmp/*.whl
RUN addgroup -g 1000 nsi_auth && adduser -D -u 1000 -G nsi_auth nsi_auth
USER nsi_auth
WORKDIR /home/nsi_auth
EXPOSE 8000/tcp
CMD ["uvicorn", "--host", "0.0.0.0", "--port", "8000", "--interface", "wsgi", "nsi_auth:app"]
