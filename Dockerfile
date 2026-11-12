FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p ft-router

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/ft-router /usr/local/bin/ft-router
EXPOSE 8787
ENTRYPOINT ["/usr/local/bin/ft-router"]
