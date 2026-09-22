# ft-router image (Plan §74–75): the Rust binary on a minimal base with no shell, as a non-root
# user. Built by CI and published to GHCR; the cluster pulls it from there.
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p ft-router

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/ft-router /usr/local/bin/ft-router
EXPOSE 8787
ENTRYPOINT ["/usr/local/bin/ft-router"]
