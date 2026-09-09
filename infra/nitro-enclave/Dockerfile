# State slice: security-alignment-os-foundation-v1.
# This image is converted to a non-debug AWS Nitro Enclave EIF by the parent.
FROM rust:1.87-bookworm

WORKDIR /build
ARG IMPLEMENTATION_REVISION
ENV IMPLEMENTATION_REVISION=${IMPLEMENTATION_REVISION}
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked \
    --bin maintenance_broker \
    --bin maintenance_evaluator \
    --bin maintenance_replication_runner \
    --bin maintenance_nitro_enclave_runner

RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin replication \
    && install -d -o replication -g replication -m 0700 /opt/maintenance/bin \
    && install -o replication -g replication -m 0700 /build/target/release/maintenance_broker /opt/maintenance/bin/maintenance_broker \
    && install -o replication -g replication -m 0700 /build/target/release/maintenance_evaluator /opt/maintenance/bin/maintenance_evaluator \
    && install -o replication -g replication -m 0700 /build/target/release/maintenance_replication_runner /opt/maintenance/bin/maintenance_replication_runner \
    && install -o replication -g replication -m 0700 /build/target/release/maintenance_nitro_enclave_runner /opt/maintenance/bin/maintenance_nitro_enclave_runner

USER replication
ENV RUST_BACKTRACE=0
ENTRYPOINT ["/opt/maintenance/bin/maintenance_nitro_enclave_runner"]
