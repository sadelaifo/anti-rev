# Self-contained test/demo image for vcachefsd (antirev design 3).
# Build context is the fusefs/ dir:  docker build -f docker/Dockerfile -t fusefs-test .
# BASE is overridable for networks where Docker Hub is blocked, e.g.
#   --build-arg BASE=public.ecr.aws/ubuntu/ubuntu:22.04
ARG BASE=ubuntu:22.04
FROM ${BASE}

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config libfuse3-dev libssl-dev fuse3 file \
        python3 python3-cryptography \
    && rm -rf /var/lib/apt/lists/*

# build the daemon (dynamic), then also verify the static build works
COPY Makefile /build/Makefile
COPY src/ /build/src/
RUN make -C /build && install -m0755 /build/vcachefsd /usr/local/bin/vcachefsd
RUN cd /build && make clean && make static \
    && install -m0755 vcachefsd /usr/local/bin/vcachefsd-static \
    && echo "=== static link check ===" \
    && (ldd /usr/local/bin/vcachefsd-static || true) \
    && file /usr/local/bin/vcachefsd-static

# bake a ciphertext "product" tree (what a shipped image would carry)
COPY docker/pack.py /build/pack.py
RUN python3 /build/pack.py /opt/product.enc /opt/expected

COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY docker/entrypoint_overlay.sh /usr/local/bin/entrypoint_overlay.sh
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/entrypoint_overlay.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
