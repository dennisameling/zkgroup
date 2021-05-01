FROM rust:1.49-slim

RUN dpkg --add-architecture arm64 && dpkg --add-architecture i386
RUN apt-get update && apt-get install -y --no-install-recommends \
    crossbuild-essential-arm64 \
    crossbuild-essential-i386

RUN rustup target add aarch64-unknown-linux-gnu i686-unknown-linux-gnu
