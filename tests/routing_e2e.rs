//! Public end-to-end coverage for consent-bound specialist routing.
//!
//! State slice: `security-alignment-os-foundation-v1`.

use security_alignment_os::memory::PersistentMemory;
use security_alignment_os::routing::{RoutingDecision, RoutingRequest};
use security_alignment_os::specialist::{
    ConsentGrant, ConsentRegistry, SpecialistIdentity, SpecialistRegistry, TenantRetrieval,
};
use std::collections::BTreeSet;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use tempfile::tempdir;

fn persistent_memory_fixtures() -> (SpecialistRegistry, ConsentRegistry, ConsentGrant) {
    let mut specialists = SpecialistRegistry::default();
    specialists
        .register(SpecialistIdentity {
            specialist_id: "memory-specialist".into(),
            version: "v1".into(),
            code_digest: "a".repeat(64),
            policy_digest: "b".repeat(64),
            issued_at: 0,
        })
        .expect("register memory specialist");
    let grant = ConsentGrant::new(
        "memory-tenant".into(),
        "memory-specialist".into(),
        BTreeSet::from(["*".into()]),
        10,
        100,
    )
    .expect("memory grant");
    let mut consents = ConsentRegistry::default();
    consents
        .grant(grant.clone())
        .expect("register memory grant");
    (specialists, consents, grant)
}

#[test]
fn route_rechecks_revocation_and_requires_a_fresh_grant_for_reconsent() {
    let mut specialists = SpecialistRegistry::default();
    specialists
        .register(SpecialistIdentity {
            specialist_id: "support-specialist".into(),
            version: "v1".into(),
            code_digest: "a".repeat(64),
            policy_digest: "b".repeat(64),
            issued_at: 5,
        })
        .expect("register specialist identity");

    let grant = ConsentGrant::new(
        "tenant-1".into(),
        "support-specialist".into(),
        BTreeSet::from(["thread-1".into()]),
        10,
        100,
    )
    .expect("consent grant");
    let request = RoutingRequest::new(
        "request-1".into(),
        "tenant-1".into(),
        "support-specialist".into(),
        grant.grant_id.clone(),
        "c".repeat(64),
        12,
        90,
    )
    .expect("routing request");
    let mut retrieval = TenantRetrieval::default();
    retrieval
        .put(
            "tenant-1".into(),
            "thread-1".into(),
            serde_json::json!({"fixture": "synthetic"}),
        )
        .expect("store synthetic retrieval fixture");
    let mut consent_registry = ConsentRegistry::default();
    consent_registry
        .grant(grant.clone())
        .expect("register consent grant");

    let decision = RoutingDecision::route(&specialists, &consent_registry, &grant, &request, 20)
        .expect("route under registered consent");
    decision
        .validate(&specialists, &consent_registry, &grant, &request, 20)
        .expect("validate route before revocation");
    assert_eq!(decision.input_digest, request.input_digest);
    assert_eq!(decision.expires_at, request.expires_at);
    assert!(retrieval
        .retrieve(&specialists, &consent_registry, &grant, "thread-1", 20)
        .is_ok());

    consent_registry
        .revoke(&grant.grant_id)
        .expect("revoke consent grant");
    assert!(decision
        .validate(&specialists, &consent_registry, &grant, &request, 20)
        .is_err());
    assert!(RoutingDecision::route(&specialists, &consent_registry, &grant, &request, 20).is_err());
    assert!(retrieval
        .retrieve(&specialists, &consent_registry, &grant, "thread-1", 20)
        .is_err());
    assert!(consent_registry.grant(grant.clone()).is_err());

    let renewed = ConsentGrant::new(
        "tenant-1".into(),
        "support-specialist".into(),
        BTreeSet::from(["thread-1".into()]),
        21,
        100,
    )
    .expect("new consent issuance");
    assert_ne!(renewed.grant_id, grant.grant_id);
    consent_registry
        .grant(renewed.clone())
        .expect("register fresh consent issuance");
    let renewed_request = RoutingRequest::new(
        "request-2".into(),
        "tenant-1".into(),
        "support-specialist".into(),
        renewed.grant_id.clone(),
        "d".repeat(64),
        22,
        90,
    )
    .expect("request under renewed consent");
    RoutingDecision::route(
        &specialists,
        &consent_registry,
        &renewed,
        &renewed_request,
        25,
    )
    .expect("route under fresh consent issuance");
}

#[test]
fn route_expires_at_the_earlier_consent_or_request_deadline() {
    let mut specialists = SpecialistRegistry::default();
    specialists
        .register(SpecialistIdentity {
            specialist_id: "specialist".into(),
            version: "v1".into(),
            code_digest: "d".repeat(64),
            policy_digest: "e".repeat(64),
            issued_at: 0,
        })
        .expect("register specialist identity");
    let grant = ConsentGrant::new(
        "tenant".into(),
        "specialist".into(),
        BTreeSet::from(["resource".into()]),
        0,
        50,
    )
    .expect("grant");
    let request = RoutingRequest::new(
        "request".into(),
        "tenant".into(),
        "specialist".into(),
        grant.grant_id.clone(),
        "f".repeat(64),
        1,
        80,
    )
    .expect("request");
    let mut consent_registry = ConsentRegistry::default();
    consent_registry
        .grant(grant.clone())
        .expect("register grant");
    let decision = RoutingDecision::route(&specialists, &consent_registry, &grant, &request, 10)
        .expect("route");
    assert_eq!(decision.expires_at, grant.expires_at);
    assert!(decision
        .validate(&specialists, &consent_registry, &grant, &request, 50)
        .is_err());
}

#[test]
fn persisted_revocation_survives_restart_for_routing_and_memory() {
    let mut specialists = SpecialistRegistry::default();
    specialists
        .register(SpecialistIdentity {
            specialist_id: "memory-specialist".into(),
            version: "v1".into(),
            code_digest: "a".repeat(64),
            policy_digest: "b".repeat(64),
            issued_at: 0,
        })
        .expect("register specialist");
    let grant = ConsentGrant::new(
        "tenant".into(),
        "memory-specialist".into(),
        BTreeSet::from(["note".into()]),
        10,
        100,
    )
    .expect("consent grant");
    let directory = tempdir().expect("temporary owner directory");
    let consent_path = directory.path().join("consent.json");
    let memory_path = directory.path().join("memory.json");
    let mut consents = ConsentRegistry::open(&consent_path).expect("open consent registry");
    consents.grant(grant.clone()).expect("register grant");
    #[cfg(unix)]
    assert_eq!(
        std::fs::metadata(&consent_path)
            .expect("consent metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let request = RoutingRequest::new(
        "request-before-revocation".into(),
        "tenant".into(),
        "memory-specialist".into(),
        grant.grant_id.clone(),
        "c".repeat(64),
        12,
        90,
    )
    .expect("request");
    let mut retrieval = TenantRetrieval::default();
    retrieval
        .put(
            "tenant".into(),
            "note".into(),
            serde_json::json!({"fixture": "synthetic"}),
        )
        .expect("store retrieval fixture");
    let mut memory = PersistentMemory::open(&memory_path).expect("open memory");
    memory
        .put(
            &specialists,
            &consents,
            &grant,
            "note",
            serde_json::json!({"value": "before-revocation"}),
            20,
        )
        .expect("persist memory under active consent");
    assert!(RoutingDecision::route(&specialists, &consents, &grant, &request, 20).is_ok());
    drop(memory);

    consents.revoke(&grant.grant_id).expect("revoke consent");
    drop(consents);

    let restored = ConsentRegistry::recover(&consent_path).expect("recover consent state");
    let mut reopened_memory = PersistentMemory::open(&memory_path).expect("reopen memory");
    let mut replayed_registry = restored.clone();
    assert!(replayed_registry.grant(grant.clone()).is_err());
    assert!(RoutingDecision::route(&specialists, &restored, &grant, &request, 20).is_err());
    assert!(retrieval
        .retrieve(&specialists, &restored, &grant, "note", 20)
        .is_err());
    assert!(reopened_memory
        .retrieve(&specialists, &restored, &grant, "note", 20)
        .is_err());
    assert!(reopened_memory
        .put(
            &specialists,
            &restored,
            &grant,
            "note",
            serde_json::json!({"value": "revoked-write"}),
            20,
        )
        .is_err());
    assert!(reopened_memory
        .delete(&specialists, &restored, &grant, "note", 20)
        .is_err());

    let renewed = ConsentGrant::new(
        "tenant".into(),
        "memory-specialist".into(),
        BTreeSet::from(["note".into()]),
        21,
        100,
    )
    .expect("new consent issuance");
    let mut renewed_registry = restored;
    renewed_registry
        .grant(renewed.clone())
        .expect("register fresh grant");
    reopened_memory
        .retrieve(&specialists, &renewed_registry, &renewed, "note", 25)
        .expect_err("old memory record remains bound to the revoked grant");
    let renewed_value = serde_json::json!({"value": "after-reconsent"});
    reopened_memory
        .put(
            &specialists,
            &renewed_registry,
            &renewed,
            "note",
            renewed_value.clone(),
            25,
        )
        .expect("write under fresh grant");
    assert_eq!(
        reopened_memory
            .retrieve(&specialists, &renewed_registry, &renewed, "note", 25)
            .expect("retrieve under fresh grant"),
        renewed_value
    );
}

#[test]
fn consent_recovery_promotes_only_a_valid_canonical_temporary_snapshot() {
    let directory = tempdir().expect("temporary owner directory");
    let path = directory.path().join("consent.json");
    let grant = ConsentGrant::new(
        "tenant".into(),
        "specialist".into(),
        BTreeSet::from(["resource".into()]),
        10,
        100,
    )
    .expect("grant");
    let mut registry = ConsentRegistry::default();
    registry.grant(grant.clone()).expect("register grant");
    registry.save(&path).expect("save active snapshot");
    let pending_path = directory.path().join("pending-consent.json");
    let mut pending_registry = registry.clone();
    pending_registry
        .revoke(&grant.grant_id)
        .expect("revoke grant");
    pending_registry
        .save(&pending_path)
        .expect("save pending revoked snapshot");
    let bytes = std::fs::read(&pending_path).expect("read pending canonical snapshot");
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, bytes).expect("write recovered snapshot");
    #[cfg(unix)]
    {
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))
            .expect("restrict recovered snapshot permissions");
    }
    let recovered = ConsentRegistry::recover(&path).expect("recover consent snapshot");
    assert!(!recovered.has_active_grant(&grant, 20));
    assert!(recovered.clone().grant(grant.clone()).is_err());
    assert!(path.is_file());
    assert!(!path.with_extension("tmp").exists());

    let canonical = std::fs::read(&path).expect("read recovered primary");
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, canonical.clone()).expect("write second recovery snapshot");
    #[cfg(unix)]
    std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))
        .expect("restrict second recovery snapshot permissions");
    std::fs::remove_file(&path).expect("remove primary to simulate interrupted replace");
    let recovered_without_primary =
        ConsentRegistry::recover(&path).expect("recover without primary");
    assert!(!recovered_without_primary.has_active_grant(&grant, 20));
    assert!(recovered_without_primary
        .clone()
        .grant(grant.clone())
        .is_err());
    assert!(!path.with_extension("tmp").exists());
    std::fs::write(&path, [canonical, b" ".to_vec()].concat()).expect("make snapshot noncanonical");
    assert!(ConsentRegistry::load(&path).is_err());
}

#[test]
fn persistent_consent_handles_preserve_revocation_against_stale_writers() {
    let directory = tempdir().expect("temporary owner directory");
    let path = directory.path().join("consent.json");
    let grant = ConsentGrant::new(
        "tenant".into(),
        "specialist".into(),
        BTreeSet::from(["resource".into()]),
        10,
        100,
    )
    .expect("grant");
    let mut current = ConsentRegistry::open(&path).expect("create persistent registry");
    current.grant(grant.clone()).expect("persist grant");
    let mut stale = ConsentRegistry::open(&path).expect("open second writer");
    let stale_export = ConsentRegistry::load(&path).expect("load stale export");

    current.revoke(&grant.grant_id).expect("persist revocation");
    assert!(stale.grant(grant.clone()).is_err());
    assert!(stale_export.save(&path).is_err());
    assert!(!stale.has_active_grant(&grant, 20));
    let recovered = ConsentRegistry::recover(&path).expect("recover persisted state");
    assert!(!recovered.has_active_grant(&grant, 20));
    assert!(recovered.clone().grant(grant).is_err());
}

#[test]
fn persistent_consent_holds_the_writer_lock_through_gated_effects() {
    use std::process::Command;
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    let directory = tempdir().expect("temporary owner directory");
    let path = directory.path().join("consent.json");
    let grant = ConsentGrant::new(
        "tenant".into(),
        "specialist".into(),
        BTreeSet::from(["resource".into()]),
        10,
        100,
    )
    .expect("grant");
    let mut owner = ConsentRegistry::open(&path).expect("create persistent registry");
    owner.grant(grant.clone()).expect("persist grant");
    let access_registry = Arc::new(ConsentRegistry::open(&path).expect("open access handle"));
    let access_grant = grant.clone();
    let revoked_id = grant.grant_id.clone();
    let (effect_started_tx, effect_started_rx) = mpsc::channel();
    let (finish_effect_tx, finish_effect_rx) = mpsc::channel();

    let access_thread = std::thread::spawn(move || {
        access_registry.with_active_grant(&access_grant, 20, || {
            effect_started_tx
                .send(())
                .expect("signal gated effect start");
            finish_effect_rx
                .recv()
                .expect("wait for gated effect release");
            Ok(())
        })
    });
    effect_started_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("gated effect acquired consent lock");

    let marker_path = directory.path().join("revocation-started");
    let mut child = Command::new(std::env::current_exe().expect("current test executable"))
        .arg("--exact")
        .arg("persistent_consent_subprocess_helper")
        .arg("--nocapture")
        .env("CONSENT_LOCK_CHILD", "1")
        .env("CONSENT_LOCK_PATH", &path)
        .env("CONSENT_LOCK_MARKER", &marker_path)
        .env("CONSENT_LOCK_GRANT_ID", &revoked_id)
        .spawn()
        .expect("spawn independent consent writer process");
    let deadline = Instant::now() + Duration::from_secs(2);
    while !marker_path.exists() && Instant::now() < deadline {
        if child.try_wait().expect("poll consent child").is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let reached_lock_attempt = marker_path.exists();
    std::thread::sleep(Duration::from_millis(50));
    let child_remained_blocked = child
        .try_wait()
        .expect("check consent child before releasing effect")
        .is_none();
    finish_effect_tx.send(()).expect("release gated effect");
    access_thread
        .join()
        .expect("access thread")
        .expect("gated effect completes");
    let child_status = child.wait().expect("wait for consent child");
    assert!(
        reached_lock_attempt,
        "child writer reached the lock attempt"
    );
    assert!(child_remained_blocked, "revocation waits for gated effect");
    assert!(
        child_status.success(),
        "child revocation succeeds after release"
    );

    let current = ConsentRegistry::open(&path).expect("reopen after revocation");
    assert!(current.with_active_grant(&grant, 20, || Ok(())).is_err());
}

#[test]
fn persistent_consent_subprocess_helper() {
    if std::env::var_os("CONSENT_LOCK_CHILD").is_none() {
        return;
    }
    let path = std::env::var_os("CONSENT_LOCK_PATH").expect("consent path");
    let marker = std::env::var_os("CONSENT_LOCK_MARKER").expect("marker path");
    let grant_id = std::env::var("CONSENT_LOCK_GRANT_ID").expect("grant id");
    std::fs::write(marker, b"started").expect("write subprocess start marker");
    let mut registry = ConsentRegistry::open(path).expect("open subprocess consent registry");
    registry
        .revoke(&grant_id)
        .expect("revoke after gated effect releases lock");
}

#[test]
fn persistent_memory_recovers_pending_snapshot_and_rejects_unsafe_files() {
    let directory = tempdir().expect("temporary owner directory");
    let path = directory.path().join("memory.json");
    let pending_source = directory.path().join("pending-source.json");
    let grant = ConsentGrant::new(
        "tenant".into(),
        "specialist".into(),
        BTreeSet::from(["resource".into()]),
        10,
        100,
    )
    .expect("grant");
    let mut specialists = SpecialistRegistry::default();
    specialists
        .register(SpecialistIdentity {
            specialist_id: "specialist".into(),
            version: "v1".into(),
            code_digest: "a".repeat(64),
            policy_digest: "b".repeat(64),
            issued_at: 0,
        })
        .expect("register specialist");
    let mut consents = ConsentRegistry::default();
    consents.grant(grant.clone()).expect("register grant");

    let mut current = PersistentMemory::open(&path).expect("open memory store");
    current
        .put(
            &specialists,
            &consents,
            &grant,
            "resource",
            serde_json::json!({"version": "primary"}),
            20,
        )
        .expect("write primary value");
    #[cfg(unix)]
    assert_eq!(
        std::fs::metadata(&path)
            .expect("memory metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    drop(current);

    let mut pending = PersistentMemory::open(&pending_source).expect("open pending source");
    let pending_value = serde_json::json!({"version": "pending"});
    pending
        .put(
            &specialists,
            &consents,
            &grant,
            "resource",
            pending_value.clone(),
            20,
        )
        .expect("write pending value");
    drop(pending);
    let pending_bytes = std::fs::read(&pending_source).expect("read pending snapshot");
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, pending_bytes).expect("stage interrupted memory snapshot");
    #[cfg(unix)]
    std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))
        .expect("restrict pending snapshot permissions");

    let recovered = PersistentMemory::open(&path).expect("promote pending memory snapshot");
    assert_eq!(
        recovered
            .retrieve(&specialists, &consents, &grant, "resource", 20)
            .expect("read recovered value"),
        pending_value
    );
    assert!(!temporary.exists());

    #[cfg(unix)]
    {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("broaden memory permissions for rejection test");
        assert!(PersistentMemory::open(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("restore owner-only memory permissions");

        let link = directory.path().join("memory-link.json");
        std::os::unix::fs::symlink(&path, &link).expect("create memory symlink");
        assert!(PersistentMemory::open(&link).is_err());
    }

    std::fs::write(&temporary, b"{} ").expect("write malformed pending snapshot");
    #[cfg(unix)]
    std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))
        .expect("restrict malformed pending snapshot permissions");
    assert!(PersistentMemory::open(&path).is_err());
}

#[test]
fn persistent_memory_subprocess_helper() {
    if std::env::var_os("PERSISTENT_MEMORY_CHILD").is_none() {
        return;
    }
    let path = std::env::var_os("PERSISTENT_MEMORY_PATH").expect("memory path");
    let (specialists, consents, grant) = persistent_memory_fixtures();
    let mut memory = PersistentMemory::open(path).expect("open child memory handle");
    let marker = std::env::var_os("PERSISTENT_MEMORY_MARKER").map(std::path::PathBuf::from);
    let start = std::env::var_os("PERSISTENT_MEMORY_START").map(std::path::PathBuf::from);
    if let Some(marker) = marker {
        std::fs::write(marker, b"ready").expect("signal child writer ready");
    }
    if let Some(start) = start {
        while !start.exists() {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        for index in 0..16 {
            let resource_id = format!("child-entry-{index}");
            memory
                .put(
                    &specialists,
                    &consents,
                    &grant,
                    &resource_id,
                    serde_json::json!({"writer": "child", "index": index}),
                    20,
                )
                .expect("concurrent child write preserves current snapshot");
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    } else {
        memory
            .put(
                &specialists,
                &consents,
                &grant,
                "child-entry",
                serde_json::json!({"writer": "child"}),
                20,
            )
            .expect("write child entry");
    }
}

#[test]
fn persistent_memory_merges_stale_handles_and_subprocess_writes() {
    use std::process::Command;
    use std::time::{Duration, Instant};

    let directory = tempdir().expect("temporary owner directory");
    let path = directory.path().join("shared-memory.json");
    let empty_path = directory.path().join("empty-memory.json");
    let mut empty = PersistentMemory::open(&empty_path).expect("open empty memory handle");
    empty.save().expect("persist initial empty snapshot");
    assert!(empty_path.exists(), "save creates the initial snapshot");
    let (specialists, consents, grant) = persistent_memory_fixtures();
    let mut initial = PersistentMemory::open(&path).expect("open initial handle");
    initial
        .put(
            &specialists,
            &consents,
            &grant,
            "seed-entry",
            serde_json::json!({"writer": "seed"}),
            20,
        )
        .expect("write seed entry");
    drop(initial);

    let mut stale = PersistentMemory::open(&path).expect("open stale handle");
    let marker = directory.path().join("child-ready");
    let start = directory.path().join("start-writers");
    let mut child = Command::new(std::env::current_exe().expect("current test executable"))
        .arg("--exact")
        .arg("persistent_memory_subprocess_helper")
        .arg("--nocapture")
        .env("PERSISTENT_MEMORY_CHILD", "1")
        .env("PERSISTENT_MEMORY_PATH", &path)
        .env("PERSISTENT_MEMORY_MARKER", &marker)
        .env("PERSISTENT_MEMORY_START", &start)
        .spawn()
        .expect("run child memory writer");
    let deadline = Instant::now() + Duration::from_secs(2);
    while !marker.exists() && Instant::now() < deadline {
        if child
            .try_wait()
            .expect("poll child memory writer")
            .is_some()
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if !marker.exists() {
        let _ = child.kill();
        let _ = child.wait();
        panic!("child memory writer reached its start barrier");
    }
    std::fs::write(&start, b"go").expect("release concurrent memory writers");
    for index in 0..16 {
        let resource_id = format!("parent-entry-{index}");
        stale
            .put(
                &specialists,
                &consents,
                &grant,
                &resource_id,
                serde_json::json!({"writer": "parent", "index": index}),
                20,
            )
            .expect("concurrent parent write preserves current snapshot");
        std::thread::sleep(Duration::from_millis(1));
    }
    let status = child.wait().expect("wait for child memory writer");
    assert!(status.success(), "child memory writer succeeds");

    stale
        .save()
        .expect("save reloads without losing child writes");
    assert_eq!(stale.len(), 33, "save refreshes the stale handle");

    let memory = PersistentMemory::open(&path).expect("reopen merged memory");
    for (resource_id, expected) in std::iter::once((
        "seed-entry".to_owned(),
        serde_json::json!({"writer": "seed"}),
    ))
    .chain((0..16).map(|index| {
        (
            format!("child-entry-{index}"),
            serde_json::json!({"writer": "child", "index": index}),
        )
    }))
    .chain((0..16).map(|index| {
        (
            format!("parent-entry-{index}"),
            serde_json::json!({"writer": "parent", "index": index}),
        )
    })) {
        assert_eq!(
            memory
                .retrieve(&specialists, &consents, &grant, &resource_id, 20)
                .expect("retrieve merged writer value"),
            expected
        );
    }
}

#[test]
fn persistent_memory_serializes_parallel_writer_handles() {
    use std::sync::{Arc, Barrier};

    let directory = tempdir().expect("temporary owner directory");
    let path = directory.path().join("parallel-memory.json");
    let (specialists, consents, grant) = persistent_memory_fixtures();
    let mut initial = PersistentMemory::open(&path).expect("open initial handle");
    initial
        .put(
            &specialists,
            &consents,
            &grant,
            "seed-entry",
            serde_json::json!({"writer": "seed"}),
            20,
        )
        .expect("write seed entry");
    drop(initial);

    let first = PersistentMemory::open(&path).expect("open first stale writer");
    let second = PersistentMemory::open(&path).expect("open second stale writer");
    let specialists = Arc::new(specialists);
    let consents = Arc::new(consents);
    let grant = Arc::new(grant);
    let barrier = Arc::new(Barrier::new(3));
    let writers = [
        ("first", first, specialists.clone(), consents.clone()),
        ("second", second, specialists.clone(), consents.clone()),
    ]
    .map(|(writer, mut memory, specialists, consents)| {
        let grant = grant.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            for index in 0..8 {
                let resource_id = format!("{writer}-{index}");
                memory
                    .put(
                        &specialists,
                        &consents,
                        &grant,
                        &resource_id,
                        serde_json::json!({"writer": writer, "index": index}),
                        20,
                    )
                    .expect("parallel writer persists without losing prior records");
            }
        })
    });
    barrier.wait();
    for writer in writers {
        writer.join().expect("parallel writer thread");
    }

    let memory = PersistentMemory::open(&path).expect("open final parallel snapshot");
    assert_eq!(memory.len(), 17);
    for writer in ["first", "second"] {
        for index in 0..8 {
            let resource_id = format!("{writer}-{index}");
            assert_eq!(
                memory
                    .retrieve(&specialists, &consents, &grant, &resource_id, 20)
                    .expect("retrieve value written by parallel handle"),
                serde_json::json!({"writer": writer, "index": index})
            );
        }
    }
}
