FROM rust:latest
WORKDIR /usr/src/app
COPY . .
RUN cargo build --release
# Copy the executable from the "build" stage.
COPY /usr/src/app/target/release/car /usr/local/bin/rust-docker
CMD ["rust-docker"]
