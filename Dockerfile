# beacon in a container. The source must include deps/monocypher
# (git clone --recursive, or git submodule update --init).
#
#   docker build -t beacon .
#   docker run -d --name beacon --restart unless-stopped --network host beacon
#
# .github/workflows/image.yml publishes it as ghcr.io/multitap-org/beacon.
#
# Use --network host: the server's whole job is to see the senders' real
# addresses, and Docker's port publishing can rewrite them (always for IPv6
# through docker-proxy). Options go after the image name (beacon --help).

FROM debian:trixie-slim AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake ninja-build g++ \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN test -f deps/monocypher/src/monocypher.c \
    || { echo "deps/monocypher is missing: git submodule update --init" >&2; exit 1; }
RUN cmake -S . -B /build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBEACON_TESTS=OFF \
    && cmake --build /build

FROM debian:trixie-slim
COPY --from=build /build/beacon /usr/local/bin/beacon
# For --status-file /status/status.json: a named volume mounted here starts
# with this directory's owner, so nobody can write to it.
RUN mkdir /status && chown nobody:nogroup /status
USER nobody
EXPOSE 55430/udp 55431/udp
ENTRYPOINT ["/usr/local/bin/beacon"]
