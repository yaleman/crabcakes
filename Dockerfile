FROM rust:1.90.0-slim-trixie AS builder

ARG GITHUB_SHA="$(git rev-parse HEAD)"
LABEL com.crabcakes.git-commit="${GITHUB_SHA}"
ARG DESCRIPTION="$(./scripts/get_description.sh)"
LABEL description="${DESCRIPTION}"

# fixing the issue with getting OOMKilled in BuildKit
RUN mkdir /crabcakes
COPY . /crabcakes/

WORKDIR /crabcakes
# install the dependencies
RUN apt-get update && apt-get -q install -y \
    git \
    clang \
    pkg-config \
    mold
ENV CC="/usr/bin/clang"
RUN cargo build --quiet --release --bin crabcakes
RUN chmod +x /crabcakes/target/release/crabcakes

# FROM gcr.io/distroless/cc-debian12 AS crabcakes
FROM rust:1.90.0-slim-trixie AS secondary


RUN apt-get -y remove --allow-remove-essential \
    binutils cpp cpp-14 gcc gcc grep gzip ncurses-bin ncurses-base sed && apt-get autoremove -y && apt-get clean && rm -rf /var/lib/apt/lists/* && rm -rf /usr/local/cargo /usr/local/rustup


# # ======================
# https://github.com/GoogleContainerTools/distroless/blob/main/examples/rust/Dockerfile
COPY --from=builder /crabcakes/target/release/crabcakes /
COPY --from=builder /crabcakes/static /static

WORKDIR /
RUN useradd -m nonroot

FROM scratch AS final
ARG DESCRIPTION="Rusty little S3-compatible object storage server"
ARG GITHUB_SHA="unknown"
LABEL DESCRIPTION="${DESCRIPTION}"
LABEL com.crabcakes.git-commit="${GITHUB_SHA}"

COPY --from=secondary / /

USER nonroot
ENTRYPOINT ["./crabcakes"]

CMD ["--host", "0.0.0.0", "--config-dir", "/config"]

