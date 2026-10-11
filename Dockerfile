# Builder: Parity's CI image ships the Rust toolchain, protoc, clang and the Wasm targets that
# Polkadot SDK builds need.
FROM docker.io/paritytech/ci-unified:latest AS builder

WORKDIR /canggu
COPY . /canggu

RUN cargo fetch --locked
RUN cargo build --locked --release -p canggu-node -p canggu-cli

# Final stage: slim runtime image with the node and the `canggu` wallet CLI.
FROM docker.io/parity/base-bin:latest

COPY --from=builder /canggu/target/release/canggu-node /usr/local/bin
COPY --from=builder /canggu/target/release/canggu /usr/local/bin

USER root
RUN useradd -m -u 1001 -U -s /bin/sh -d /canggu canggu && \
	mkdir -p /data /canggu/.local/share && \
	chown -R canggu:canggu /data && \
	ln -s /data /canggu/.local/share/canggu-node && \
	/usr/local/bin/canggu-node --version

USER canggu

EXPOSE 30333 9944 9615
VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/canggu-node"]
CMD ["--dev", "--rpc-external"]
