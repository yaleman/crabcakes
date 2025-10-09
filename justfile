git := require("git")
cargo := require("cargo")
pnpm := require("pnpm")
npx := require("npx")

default:
    just --list

# run the linter, tests, and format the code
check:
    cargo clippy --all-targets --quiet --workspace
    cargo test --quiet --workspace
    cargo fmt --all
    pnpm run lint

# build JavaScript bundles
build-js:
    @echo "Bundling files..."
    pnpm run build
    @echo "Finished at $(date)"

# lint JavaScript and CSS files
lint-web:
    pnpm run lint

# lint CSS only
lint-css:
    pnpm run lint:css

# run coverage checks
coverage:
    cargo tarpaulin --out=Html

# build the docker image
docker_build:
    docker buildx build \
        --load \
        --build-arg "GITHUB_SHA=$(git rev-parse HEAD)" \
        --build-arg "DESCRIPTION=$(./scripts/get_description.sh)" \
        --tag ghcr.io/yaleman/crabcakes:latest \
        .

# build and run the docker image, mounting ./config as the config dir
docker_run: docker_build
    docker run --rm -it \
        -p 9000:9000 \
        --mount type=bind,src=$(pwd)/config,target=/config \
        ghcr.io/yaleman/crabcakes:latest

run: build-js
    cargo run --

run_debug: build-js
    RUST_LOG=debug cargo run

# run mdbook in "serve" mode
serve_docs:
    cd docs && mdbook serve