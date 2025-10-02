check:
    cargo clippy --all-targets --quiet
    cargo test --quiet
    cargo fmt
coverage:
    cargo tarpaulin --out=Html


docker_build:
    docker buildx build --load --tag ghcr.io/yaleman/crabcakes:latest .

docker_run: docker_build
    docker run --rm -it \
        -p 8090:8090 \
        --mount type=bind,src=$(pwd)/config,target=/config \
        ghcr.io/yaleman/crabcakes:latest