//! Real Linux metadata boundary tests, not a swap or cryptographic benchmark.
//! The original lexical scanner is never instrumented or replaced here.
use super::*;
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ObservationsV25 {
    passes: [usize; 3],
    entries: [usize; 3],
    fallbacks: usize,
}

thread_local! {
    // Opt-in, per-test-thread counters. Other tests and ordinary Store scans
    // cannot contribute to these measurements, even under parallel libtest.
    static OBSERVATIONS_V25: RefCell<Option<ObservationsV25>> = const { RefCell::new(None) };
}

pub(super) fn observe_pass_v25(phase: usize) {
    OBSERVATIONS_V25.with(|cell| {
        if let Some(state) = cell.borrow_mut().as_mut() {
            state.passes[phase] += 1;
        }
    });
}

pub(super) fn observe_entry_v25(phase: usize) {
    OBSERVATIONS_V25.with(|cell| {
        if let Some(state) = cell.borrow_mut().as_mut() {
            state.entries[phase] += 1;
        }
    });
}

pub(super) fn observe_fallback_v25() {
    OBSERVATIONS_V25.with(|cell| {
        if let Some(state) = cell.borrow_mut().as_mut() {
            state.fallbacks += 1;
        }
    });
}

struct ObservationGuardV25;
impl ObservationGuardV25 {
    fn begin() -> Self {
        OBSERVATIONS_V25.with(|cell| {
            assert!(cell.replace(Some(ObservationsV25::default())).is_none());
        });
        Self
    }
    fn read(&self) -> ObservationsV25 {
        OBSERVATIONS_V25.with(|cell| cell.borrow().unwrap())
    }
}
impl Drop for ObservationGuardV25 {
    fn drop(&mut self) {
        OBSERVATIONS_V25.with(|cell| {
            cell.replace(None);
        });
    }
}

fn filename(sequence: u64) -> String {
    format!("{sequence:020}-{sequence:064x}.journal")
}

fn journal(
    root: &RetainedDirectory,
    sequences: &[u64],
) -> Result<RetainedDirectory, LinuxCapabilityError> {
    let journal = root.create_child_directory(ValidatedComponent::registered("journal")?)?;
    for sequence in sequences {
        journal.create_immutable_file(
            &ValidatedComponent::registered(&filename(*sequence))?,
            &sequence.to_le_bytes(),
        )?;
    }
    Ok(journal)
}

type PublicInventoryV25 = Vec<(String, NodeIdentity, Vec<u8>)>;

fn collect(
    directory: &RetainedDirectory,
    unordered: bool,
) -> Result<PublicInventoryV25, LinuxCapabilityError> {
    let mut result = Vec::new();
    let mut inspect = |name: &str, identity| {
        let bytes = directory.read_bounded_file(&ValidatedComponent::registered(name)?, 8)?;
        result.push((name.to_owned(), identity, bytes));
        Ok(())
    };
    if unordered {
        directory.scan_unordered_readonly_with_exclusions_v25(&mut inspect)?;
    } else {
        directory.scan_lexicographic(&mut inspect)?;
    }
    result.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(result)
}

fn private_write(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(FILE_MODE))?;
    Ok(())
}

#[test]
fn unordered_readonly_static_corpus_matches_original_inventory_v25() -> Result<(), Box<dyn Error>> {
    for sequences in [vec![], vec![1], vec![9, 1, 12, 3], (1..=32).rev().collect()] {
        super::tests::with_root_v25(|_, root| {
            let directory = journal(root, &sequences)?;
            assert_eq!(collect(&directory, true)?, collect(&directory, false)?);
            // A fresh independent scan must see the complete same inventory.
            assert_eq!(collect(&directory, true)?.len(), sequences.len());
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn unordered_readonly_physical_refusals_match_original_before_callbacks_v25(
) -> Result<(), Box<dyn Error>> {
    for case in 0..6 {
        super::tests::with_root_v25(|path, root| {
            let directory = journal(root, &[1, 2])?;
            let base = path.join("contracts-store/journal");
            let expected = match case {
                0 => {
                    private_write(&base.join("unknown"), b"bad")?;
                    LinuxCapabilityError::InvalidComponent
                }
                1 => {
                    let wrong_type = base.join(filename(3));
                    fs::create_dir(&wrong_type)?;
                    fs::set_permissions(wrong_type, fs::Permissions::from_mode(DIRECTORY_MODE))?;
                    LinuxCapabilityError::InvalidObject
                }
                2 => {
                    fs::set_permissions(base.join(filename(1)), fs::Permissions::from_mode(0o644))?;
                    LinuxCapabilityError::InvalidObject
                }
                3 => {
                    symlink(base.join(filename(1)), base.join(filename(3)))?;
                    LinuxCapabilityError::InvalidObject
                }
                4 => {
                    fs::hard_link(base.join(filename(1)), path.join("held-hardlink"))?;
                    LinuxCapabilityError::InvalidObject
                }
                5 => {
                    fs::set_permissions(&base, fs::Permissions::from_mode(0o755))?;
                    LinuxCapabilityError::InvalidObject
                }
                _ => unreachable!(),
            };
            for unordered in [false, true] {
                let mut callbacks = 0;
                let mut inspect = |_: &str, _| {
                    callbacks += 1;
                    Ok(())
                };
                let result = if unordered {
                    directory.scan_unordered_readonly_with_exclusions_v25(&mut inspect)
                } else {
                    directory.scan_lexicographic(&mut inspect)
                };
                assert_eq!(result, Err(expected));
                assert_eq!(callbacks, 0, "physical preflight precedes every callback");
            }
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn unordered_readonly_exclusions_pin_identity_and_snapshot_without_callback_lock_v25(
) -> Result<(), Box<dyn Error>> {
    super::tests::with_root_v25(|_, root| {
        let directory = journal(root, &[1, 2, 3])?;
        let excluded = filename(1);
        let retained = directory.open_file(&ValidatedComponent::registered(&excluded)?, false)?;
        directory
            .install_scan_exclusions(BTreeMap::from([(excluded.clone(), retained.identity)]))?;
        assert_eq!(collect(&directory, true)?, collect(&directory, false)?);
        let mut seen = BTreeSet::new();
        directory.scan_unordered_readonly_with_exclusions_v25(|name, _| {
            assert!(seen.insert(name.to_owned()));
            assert_ne!(name, excluded);
            if seen.len() == 1 {
                // This would deadlock if preflight retained its exclusions lock
                // across callbacks. The current scan still uses its old snapshot.
                directory.clear_scan_exclusions()?;
                assert_eq!(collect(&directory, true)?.len(), 3);
            }
            Ok(())
        })?;
        assert_eq!(seen.len(), 2);
        assert!(!seen.contains(&excluded));
        Ok(())
    })
}

#[test]
fn unordered_readonly_excluded_replacement_refuses_before_and_after_collection_v25(
) -> Result<(), Box<dyn Error>> {
    for after_collection in [false, true] {
        super::tests::with_root_v25(|path, root| {
            let directory = journal(root, &[1, 2, 3])?;
            let name = filename(1);
            // Keep the old descriptor open so the replacement cannot reuse its inode.
            let retained = directory.open_file(&ValidatedComponent::registered(&name)?, false)?;
            directory
                .install_scan_exclusions(BTreeMap::from([(name.clone(), retained.identity)]))?;
            let replacement = path.join("replacement");
            private_write(&replacement, b"new")?;
            let destination = path.join("contracts-store/journal").join(&name);
            if !after_collection {
                fs::rename(&replacement, &destination)?;
                assert_eq!(
                    collect(&directory, false),
                    Err(LinuxCapabilityError::IdentityMismatch)
                );
            }
            let mut callbacks = 0;
            let outcome = directory.scan_unordered_readonly_with_exclusions_v25(|_, _| {
                callbacks += 1;
                if after_collection && callbacks == 2 {
                    fs::rename(&replacement, &destination).unwrap();
                }
                Ok(())
            });
            assert_eq!(outcome, Err(LinuxCapabilityError::IdentityMismatch));
            assert_eq!(callbacks, if after_collection { 2 } else { 0 });
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn unordered_readonly_persistent_namespace_mutations_refuse_without_replaying_callbacks_v25(
) -> Result<(), Box<dyn Error>> {
    for case in 0..6 {
        super::tests::with_root_v25(|path, root| {
            let directory = journal(root, &[1, 2])?;
            let base = path.join("contracts-store/journal");
            let old = directory.open_file(&ValidatedComponent::registered(&filename(1))?, false)?;
            let replacement = path.join("replacement");
            private_write(&replacement, b"changed")?;
            let mut seen = BTreeSet::new();
            let outcome = directory.scan_unordered_readonly_with_exclusions_v25(|name, _| {
                assert!(
                    seen.insert(name.to_owned()),
                    "callbacks must never be replayed"
                );
                if seen.len() == 2 {
                    match case {
                        // A valid added name is a mismatch too: merely validating
                        // physical types in postflight would incorrectly accept it.
                        0 => private_write(&base.join(filename(3)), b"new").unwrap(),
                        1 => fs::remove_file(base.join(filename(1))).unwrap(),
                        2 => fs::rename(&replacement, base.join(filename(1))).unwrap(),
                        3 => private_write(&base.join("unknown"), b"bad").unwrap(),
                        4 => fs::set_permissions(
                            base.join(filename(1)),
                            fs::Permissions::from_mode(0o644),
                        )
                        .unwrap(),
                        5 => {
                            // Registered but not a record: postflight must notice
                            // membership, not only the component registry/type.
                            fs::create_dir(base.join("journal")).unwrap();
                            fs::set_permissions(
                                base.join("journal"),
                                fs::Permissions::from_mode(DIRECTORY_MODE),
                            )
                            .unwrap();
                        }
                        _ => unreachable!(),
                    }
                }
                Ok(())
            });
            assert!(outcome.is_err(), "persistent mutation {case} must refuse");
            assert_eq!(seen.len(), 2);
            drop(old);
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn unordered_readonly_moved_directory_refuses_after_last_callback_v25() -> Result<(), Box<dyn Error>>
{
    super::tests::with_root_v25(|path, root| {
        let directory = journal(root, &[1, 2])?;
        let canonical = path.join("contracts-store/journal");
        let mut callbacks = 0;
        let outcome = directory.scan_unordered_readonly_with_exclusions_v25(|_, _| {
            callbacks += 1;
            if callbacks == 2 {
                fs::rename(&canonical, path.join("displaced-journal")).unwrap();
                fs::create_dir(&canonical).unwrap();
                fs::set_permissions(&canonical, fs::Permissions::from_mode(DIRECTORY_MODE))
                    .unwrap();
            }
            Ok(())
        });
        assert_eq!(outcome, Err(LinuxCapabilityError::IdentityMismatch));
        assert_eq!(callbacks, 2);
        Ok(())
    })
}

#[test]
fn unordered_readonly_callback_error_is_exact_and_never_retried_v25() -> Result<(), Box<dyn Error>>
{
    super::tests::with_root_v25(|_, root| {
        let directory = journal(root, &[1, 2, 3])?;
        for expected in [
            LinuxCapabilityError::StoreBusy,
            LinuxCapabilityError::NotFound,
            LinuxCapabilityError::InvalidComponent,
            LinuxCapabilityError::InvalidObject,
            LinuxCapabilityError::ExactBytesMismatch,
            LinuxCapabilityError::IdentityMismatch,
            LinuxCapabilityError::OperationFailed {
                operation: "test-readonly-collector",
                os_code: None,
            },
        ] {
            let mut callbacks = 0;
            let observations = ObservationGuardV25::begin();
            let outcome = directory.scan_unordered_readonly_with_exclusions_v25(|_, _| {
                callbacks += 1;
                Err(expected)
            });
            assert_eq!(outcome, Err(expected));
            assert_eq!(callbacks, 1);
            assert_eq!(observations.read().passes, [1, 1, 0]);
            assert_eq!(observations.read().fallbacks, 0);
        }
        Ok(())
    })
}

#[test]
fn unordered_readonly_small_budget_falls_back_before_any_callback_v25() -> Result<(), Box<dyn Error>>
{
    super::tests::with_root_v25(|_, root| {
        let directory = journal(root, &[9, 1, 12, 3])?;
        let mut original = Vec::new();
        directory.scan_lexicographic(|name, _| {
            original.push(name.to_owned());
            Ok(())
        })?;
        for limit in [0, 1, 3] {
            let observations = ObservationGuardV25::begin();
            let mut collected = Vec::new();
            directory.scan_unordered_readonly_bounded_v25(limit, |name, _| {
                collected.push(name.to_owned());
                Ok(())
            })?;
            assert_eq!(collected, original);
            assert_eq!(observations.read().passes, [1, 0, 0]);
            assert_eq!(observations.read().entries, [4, 0, 0]);
            assert_eq!(observations.read().fallbacks, 1);
        }
        Ok(())
    })?;
    super::tests::with_root_v25(|path, root| {
        let directory = journal(root, &[1, 2])?;
        private_write(&path.join("contracts-store/journal/unknown"), b"bad")?;
        let observations = ObservationGuardV25::begin();
        let mut callbacks = 0;
        assert_eq!(
            directory.scan_unordered_readonly_bounded_v25(0, |_, _| {
                callbacks += 1;
                Ok(())
            }),
            Err(LinuxCapabilityError::InvalidComponent)
        );
        assert_eq!(callbacks, 0);
        assert_eq!(
            observations.read().fallbacks,
            0,
            "physical failure is not overflow"
        );
        Ok(())
    })
}

#[test]
fn unordered_readonly_measures_three_physical_passes_and_one_callback_per_entry_v25(
) -> Result<(), Box<dyn Error>> {
    super::tests::with_root_v25(|_, root| {
        let directory = journal(root, &(1..=64).rev().collect::<Vec<_>>())?;
        let observations = ObservationGuardV25::begin();
        let mut names = BTreeSet::new();
        directory.scan_unordered_readonly_with_exclusions_v25(|name, _| {
            assert!(names.insert(name.to_owned()));
            Ok(())
        })?;
        assert_eq!(names.len(), 64);
        assert_eq!(
            observations.read(),
            ObservationsV25 {
                passes: [1; 3],
                entries: [64; 3],
                fallbacks: 0,
            }
        );
        // These counters observe the three actual scan_independent calls and
        // their validated entries. No original-scanner syscall count or elapsed
        // swap-time improvement is fabricated from the N(N+1) source formula.
        Ok(())
    })
}
