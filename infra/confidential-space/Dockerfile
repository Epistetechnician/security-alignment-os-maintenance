# State slice: security-alignment-os-foundation-v1.
# The Rust toolchain remains in the runtime image because the existing runner
# records `rustc -Vv` as part of its report binding.
FROM rust:1.87-bookworm

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked \
    --bin maintenance_broker \
    --bin maintenance_evaluator \
    --bin maintenance_replication_runner \
    --bin maintenance_confidential_space_runner

RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin replication \
    && install -d -o replication -g replication -m 0700 /run/maintenance \
    && install -d -o replication -g replication -m 0700 /opt/maintenance/bin \
    && install -o replication -g replication -m 0700 /build/target/release/maintenance_broker /opt/maintenance/bin/maintenance_broker \
    && install -o replication -g replication -m 0700 /build/target/release/maintenance_evaluator /opt/maintenance/bin/maintenance_evaluator \
    && install -o replication -g replication -m 0700 /build/target/release/maintenance_replication_runner /opt/maintenance/bin/maintenance_replication_runner \
    && install -o replication -g replication -m 0700 /build/target/release/maintenance_confidential_space_runner /opt/maintenance/bin/maintenance_confidential_space_runner

USER replication
ENTRYPOINT ["/opt/maintenance/bin/maintenance_confidential_space_runner"]
