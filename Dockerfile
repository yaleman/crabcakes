FROM debian:12 AS builder

ARG GITHUB_SHA="$(git rev-parse HEAD)"

LABEL com.crabcakes.git-commit="${GITHUB_SHA}"

# fixing the issue with getting OOMKilled in BuildKit
RUN mkdir /crabcakes
COPY . /crabcakes/

WORKDIR /crabcakes
# install the dependencies
RUN apt-get update && apt-get install -y \
    curl \
    clang \
    git \
    build-essential \
    pkg-config \
    mold
# install rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
RUN mv /root/.cargo/bin/* /usr/local/bin/
# do the build bits
ENV CC="/usr/bin/clang"
RUN cargo build --quiet --release --bin crabcakes
RUN chmod +x /crabcakes/target/release/crabcakes

FROM gcr.io/distroless/cc-debian12 AS crabcakes
# # ======================
# https://github.com/GoogleContainerTools/distroless/blob/main/examples/rust/Dockerfile
COPY --from=builder /crabcakes/target/release/crabcakes /
COPY --from=builder /crabcakes/static /static
COPY --from=builder /crabcakes/templates /templates

WORKDIR /
USER nonroot
ENTRYPOINT ["./crabcakes"]

CMD ["--host", "0.0.0.0", "--config-dir", "/config"]
