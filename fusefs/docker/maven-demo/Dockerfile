# maven-demo: prove `mvn test` passes over an ENCRYPTED Maven repo via fusefs.
# Build context = fusefs/ :  docker build -f docker/maven-demo/Dockerfile -t fusefs-mvn .
ARG BASE=ubuntu:22.04
FROM ${BASE}

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config libfuse3-dev libssl-dev fuse3 \
        openjdk-17-jdk maven python3 python3-cryptography ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# build the daemon
COPY Makefile /build/Makefile
COPY src/ /build/src/
RUN make -C /build && install -m0755 /build/vcachefsd /usr/local/bin/vcachefsd

# tools used by the demo/script
COPY docker/jar-demo/pack_jar.py        /usr/local/bin/pack_jar.py
COPY examples/protect-maven-repo.sh     /usr/local/bin/protect-maven-repo.sh
RUN chmod +x /usr/local/bin/protect-maven-repo.sh

# the demo project; populate ~/.m2 at build time (online) so the run is offline
COPY docker/maven-demo/project /proj
RUN cd /proj && mvn -B -q test && echo "[build] ~/.m2 populated, baseline green"

COPY docker/maven-demo/entrypoint_maven.sh /usr/local/bin/entrypoint_maven.sh
RUN chmod +x /usr/local/bin/entrypoint_maven.sh
ENTRYPOINT ["/usr/local/bin/entrypoint_maven.sh"]
