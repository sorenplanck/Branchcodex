//! Exact V3 -> V4 upgrade for all five settlement faces.
//!
//! Old V3 used face tags 1..3; the validated V18 also used version 3 but
//! widened that one CHECK to 1..5. Both exact layouts are recognized. No
//! arbitrary SQL, caller-provided migration or edited schema is accepted.
use super::*;

fn legacy_schema(three_faces: bool) -> String {
    let schema = SCHEMA_V4.replace("PRAGMA user_version = 4;", "PRAGMA user_version = 3;");
    if three_faces {
        schema.replace("face_tag BETWEEN 1 AND 5", "face_tag BETWEEN 1 AND 3")
    } else {
        schema
    }
}

pub(super) fn require_exact_v3(connection: &Connection) -> Result<()> {
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(storage)?;
    if version != 3 {
        return Err(CoordinatorErrorV1::UnsupportedFormat);
    }
    let actual = schema_objects(connection)?;
    for three_faces in [true, false] {
        let reference = Connection::open_in_memory().map_err(storage)?;
        reference
            .execute_batch(&legacy_schema(three_faces))
            .map_err(storage)?;
        if actual == schema_objects(&reference)? {
            return Ok(());
        }
    }
    Err(CoordinatorErrorV1::CorruptState)
}

pub(super) fn migrate(
    connection: &mut Connection,
    coordinator: Digest32,
    authority: Digest32,
    pristine_only: bool,
) -> Result<()> {
    migrate_with_hook(connection, coordinator, authority, pristine_only, || Ok(()))
}

fn migrate_with_hook(
    connection: &mut Connection,
    coordinator: Digest32,
    authority: Digest32,
    pristine_only: bool,
    before_commit: impl FnOnce() -> Result<()>,
) -> Result<()> {
    // The caller owns the validated physical database and exclusive process
    // lock. Do not toggle FK enforcement inside an existing transaction.
    if !connection.is_autocommit() {
        return Err(CoordinatorErrorV1::InvalidState);
    }
    require_exact_v3(connection)?;
    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .map_err(storage)?;
    let outcome = (|| -> Result<()> {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        require_exact_v3(&transaction)?;
        let application: i64 = transaction
            .query_row("PRAGMA application_id", [], |r| r.get(0))
            .map_err(storage)?;
        let metadata: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = transaction.query_row(
            "SELECT coordinator_id,plan_authority_id,clock_high_water_be,created_at_be FROM coordinator_metadata WHERE singleton=1",
            [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).map_err(storage)?;
        let count: i64 = transaction
            .query_row("SELECT COUNT(*) FROM coordinator_metadata", [], |r| {
                r.get(0)
            })
            .map_err(storage)?;
        if application != 0
            || count != 1
            || blob_u64(metadata.2.clone())? < blob_u64(metadata.3.clone())?
        {
            return Err(CoordinatorErrorV1::CorruptState);
        }
        if blob32(metadata.0)? != coordinator || blob32(metadata.1)? != authority {
            return Err(CoordinatorErrorV1::InvalidStorageAuthority);
        }
        integrity(&transaction)?;
        let plans = plan_ids(&transaction)?;
        for plan in &plans {
            audit_plan(&transaction, *plan)?;
        }
        if pristine_only {
            // Creation recovery may never adopt an existing economic state.
            for table in [
                "settlement_plans",
                "settlement_plan_versions",
                "settlement_children",
                "deferred_child_materializations",
                "coordinator_leases",
                "coordinator_journal",
                "child_call_outcomes",
                "child_reconciliation_calls",
                "observation_calls",
                "coordinator_conflicts",
            ] {
                let count: i64 = transaction
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
                    .map_err(storage)?;
                if count != 0 {
                    return Err(CoordinatorErrorV1::CorruptState);
                }
            }
            if metadata.2 != metadata.3 {
                return Err(CoordinatorErrorV1::CorruptState);
            }
        }
        let children: i64 = transaction
            .query_row("SELECT COUNT(*) FROM settlement_children", [], |r| r.get(0))
            .map_err(storage)?;
        if !(0..=8192).contains(&children) {
            return Err(CoordinatorErrorV1::CorruptState);
        }
        // Recreate the table under its ORIGINAL name, so foreign-key SQL and
        // the exact schema text do not acquire ALTER TABLE name rewriting.
        // This temporary copy lives only inside this SQLite transaction.
        transaction.execute_batch("CREATE TEMP TABLE dom_children_upgrade_v19 AS SELECT * FROM settlement_children; DROP TABLE settlement_children;")
            .map_err(storage)?;
        let (_, suffix) = SCHEMA_V4
            .split_once("CREATE TABLE settlement_children (")
            .ok_or(CoordinatorErrorV1::UnsupportedFormat)?;
        let (body, _) = suffix
            .split_once(") STRICT;")
            .ok_or(CoordinatorErrorV1::UnsupportedFormat)?;
        transaction
            .execute_batch(&format!(
                "CREATE TABLE settlement_children ({body}) STRICT;"
            ))
            .map_err(storage)?;
        transaction
            .execute_batch(
                "INSERT INTO settlement_children SELECT * FROM temp.dom_children_upgrade_v19;",
            )
            .map_err(storage)?;
        let copied: i64 = transaction
            .query_row("SELECT COUNT(*) FROM settlement_children", [], |r| r.get(0))
            .map_err(storage)?;
        let different: bool = transaction.query_row(
            "SELECT EXISTS(SELECT * FROM settlement_children EXCEPT SELECT * FROM temp.dom_children_upgrade_v19)
                 OR EXISTS(SELECT * FROM temp.dom_children_upgrade_v19 EXCEPT SELECT * FROM settlement_children)",
            [], |r| r.get(0)).map_err(storage)?;
        if copied != children || different {
            return Err(CoordinatorErrorV1::CorruptState);
        }
        transaction
            .execute_batch("DROP TABLE temp.dom_children_upgrade_v19; PRAGMA user_version = 4;")
            .map_err(storage)?;
        // Every existing economic byte and journal is revalidated before
        // commit. No lease, fence, authority identity or receipt is replaced.
        validate_backend_and_schema(&transaction)?;
        for plan in plans {
            audit_plan(&transaction, plan)?;
        }
        before_commit()?;
        transaction.commit().map_err(storage)
    })();
    // Restore this connection's strict setting on success AND rollback.
    // The owning open drops the connection if either operation fails.
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(storage)?;
    let enabled: i64 = connection
        .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
        .map_err(storage)?;
    if enabled != 1 {
        return Err(CoordinatorErrorV1::UnsupportedFormat);
    }
    outcome?;
    validate_backend_and_schema(connection)
}

fn integrity(connection: &Connection) -> Result<()> {
    let quick: String = connection
        .query_row("PRAGMA quick_check(1)", [], |r| r.get(0))
        .map_err(storage)?;
    let broken: i64 = connection
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| {
            r.get(0)
        })
        .map_err(storage)?;
    if quick != "ok" || broken != 0 {
        return Err(CoordinatorErrorV1::CorruptState);
    }
    Ok(())
}

fn plan_ids(connection: &Connection) -> Result<Vec<Digest32>> {
    let mut statement = connection
        .prepare("SELECT plan_id FROM settlement_plans ORDER BY plan_id LIMIT 4097")
        .map_err(storage)?;
    let rows = statement
        .query_map([], |r| r.get::<_, Vec<u8>>(0))
        .map_err(storage)?;
    let mut ids = Vec::new();
    for row in rows {
        ids.push(blob32(row.map_err(storage)?)?);
    }
    if ids.len() > 4096 {
        return Err(CoordinatorErrorV1::CorruptState);
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(three_faces: bool) -> Result<Connection> {
        let connection = Connection::open_in_memory().map_err(storage)?;
        connection
            .execute_batch(&legacy_schema(three_faces))
            .map_err(storage)?;
        connection
            .execute(
                "INSERT INTO coordinator_metadata VALUES(1,?1,?2,?3,?3)",
                params![[1u8; 32].as_slice(), [2u8; 32].as_slice(), u64_blob(10)],
            )
            .map_err(storage)?;
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .map_err(storage)?;
        Ok(connection)
    }
    #[test]
    fn v19_accepts_both_exact_v3_layouts() -> Result<()> {
        for three_faces in [true, false] {
            let mut connection = fixture(three_faces)?;
            migrate(&mut connection, [1; 32], [2; 32], false)?;
            validate_backend_and_schema(&connection)?;
            let fk: i64 = connection
                .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
                .map_err(storage)?;
            assert_eq!(fk, 1);
        }
        Ok(())
    }
    #[test]
    fn v19_migration_rollback_preserves_version_schema_and_identity() -> Result<()> {
        let mut connection = fixture(true)?;
        let before = schema_objects(&connection)?;
        assert_eq!(
            migrate_with_hook(&mut connection, [1; 32], [2; 32], false, || Err(
                CoordinatorErrorV1::StorageUnavailable
            )),
            Err(CoordinatorErrorV1::StorageUnavailable)
        );
        assert_eq!(schema_objects(&connection)?, before);
        require_exact_v3(&connection)?;
        migrate(&mut connection, [1; 32], [2; 32], false)?;
        Ok(())
    }
    #[test]
    fn v19_refuses_wrong_owner_and_modified_schema() -> Result<()> {
        let mut connection = fixture(true)?;
        assert_eq!(
            migrate(&mut connection, [3; 32], [2; 32], false),
            Err(CoordinatorErrorV1::InvalidStorageAuthority)
        );
        require_exact_v3(&connection)?;
        connection
            .execute_batch("CREATE TABLE extra(value INTEGER) STRICT;")
            .map_err(storage)?;
        assert_eq!(
            migrate(&mut connection, [1; 32], [2; 32], false),
            Err(CoordinatorErrorV1::CorruptState)
        );
        Ok(())
    }
}
