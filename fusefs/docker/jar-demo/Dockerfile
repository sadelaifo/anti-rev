# jar-demo: prove a JVM runs an ENCRYPTED .jar through the fusefs mount.
# Build context = fusefs/ :  docker build -f docker/jar-demo/Dockerfile -t fusefs-jar .
ARG BASE=ubuntu:22.04
FROM ${BASE}

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config libfuse3-dev libssl-dev fuse3 \
        default-jdk python3 python3-cryptography \
    && rm -rf /var/lib/apt/lists/*

COPY Makefile /build/Makefile
COPY src/ /build/src/
RUN make -C /build && install -m0755 /build/vcachefsd /usr/local/bin/vcachefsd

# a tiny runnable jar (stands in for your product jar)
RUN mkdir -p /j \
 && printf 'public class Hello { public static void main(String[] a){ System.out.println("Hello from encrypted jar"); } }\n' > /j/Hello.java \
 && cd /j && javac Hello.java && jar cfe app.jar Hello Hello.class && ls -l /j/app.jar

# encrypt it into the ciphertext lower tree (embedded-key container, FS_MAGIC).
# Use a COPY'd script (the legacy builder has no RUN-heredoc support).
COPY docker/jar-demo/pack_jar.py /build/pack_jar.py
RUN python3 /build/pack_jar.py /j/app.jar /opt/app.enc/app.jar

COPY docker/jar-demo/entrypoint_jar.sh /usr/local/bin/entrypoint_jar.sh
RUN chmod +x /usr/local/bin/entrypoint_jar.sh
ENTRYPOINT ["/usr/local/bin/entrypoint_jar.sh"]
