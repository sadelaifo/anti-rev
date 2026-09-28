# syntax=docker/dockerfile:1
# Production image for an encrypted /app/bin/dose.jar, decrypted in place by
# vcachefsd at container start.  Build context = the antirev repo root (so
# `fusefs/` and `shared/` are visible), with your dose.jar and entrypoint.sh here.
#
# Build (BuildKit, key passed as a secret so it never lands in an image layer):
#   DOCKER_BUILDKIT=1 docker build -f fusefs/examples/jar-inplace/Dockerfile \
#       --secret id=fusekey,src=/path/to/master.key.hex \
#       --build-arg JRE_BASE=amazoncorretto:21 -t dose:enc .
# Run:
#   docker run -d --cap-add SYS_ADMIN --device /dev/fuse dose:enc

ARG JRE_BASE=amazoncorretto:21           # your real JRE base (RHEL-family here -> yum)

# ── stage 1: build vcachefsd with the master key baked in ────────────────────
FROM rockylinux:9 AS build
RUN yum install -y gcc make cmake fuse3-devel openssl-devel pkgconfig python3 \
    && yum clean all
COPY fusefs/ /src/fusefs/
COPY shared/ /src/shared/
RUN --mount=type=secret,id=fusekey \
    python3 /src/shared/gen_key_blob.py /run/secrets/fusekey /src/fusefs/src/key_blob.c \
 && make -C /src/fusefs \
 && install -m 0755 /src/fusefs/vcachefsd /vcachefsd

# ── stage 2: encrypt dose.jar with the SAME key (keyless FS_MAGIC container) ──
FROM rockylinux:9 AS pack
RUN yum install -y python3 python3-pip \
    && pip3 install --no-cache-dir cryptography pyyaml \
    && yum clean all
COPY shared/ /src/shared/
COPY dose.jar /plain/bin/dose.jar
RUN --mount=type=secret,id=fusekey \
    printf 'install_dir: /plain/bin\noutput_dir: /enc/bin\nkey: /run/secrets/fusekey\nencrypt_ext: [".jar"]\nmirror_plaintext: false\n' > /pack.yaml \
 && python3 /src/shared/vcache-pack.py /pack.yaml        # -> /enc/bin/dose.jar (ciphertext)

# ── final: your product image ────────────────────────────────────────────────
FROM ${JRE_BASE}
# fusermount3 (the setuid mount helper vcachefsd execs). RHEL-family -> yum.
# Debian/Ubuntu base -> replace with: apt-get update && apt-get install -y fuse3
RUN yum install -y fuse3 && yum clean all
COPY --from=build /vcachefsd                                 /usr/local/bin/vcachefsd
COPY --from=pack  /enc/bin/dose.jar                          /app/bin/dose.jar
COPY fusefs/examples/jar-inplace/entrypoint.sh               /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/vcachefsd /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["java", "-jar", "/app/bin/dose.jar"]
