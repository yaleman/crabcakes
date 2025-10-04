default:
    just --list

# run the linter, tests, and format the code
check:
    cargo clippy --all-targets --quiet
    cargo test --quiet
    cargo fmt
    pnpm run lint

# build JavaScript bundles
build-js:
    pnpm run build

# lint JavaScript and CSS files
lint-web:
    pnpm run lint

# lint JavaScript only
lint-js:
    pnpm run lint:js

# lint CSS only
lint-css:
    pnpm run lint:css

# run coverage checks
coverage:
    cargo tarpaulin --out=Html

# build the docker image
docker_build:
    docker buildx build --load --tag ghcr.io/yaleman/crabcakes:latest .

# build and run the docker image, mounting ./config as the config dir
docker_run: docker_build
    docker run --rm -it \
        -p 8090:8090 \
        --mount type=bind,src=$(pwd)/config,target=/config \
        ghcr.io/yaleman/crabcakes:latest