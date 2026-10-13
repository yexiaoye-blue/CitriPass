//! Release timings for the binary vault format.
//!
//! Iteration counts for the shared scenarios match the previous example.
//! Each scenario is warmed up once per round. Three rounds run back to back;
//! the reported value is the median.

use std::hint::black_box;
use std::time::Instant;
use vault_core::{
    generate_password, ItemData, ItemDraft, PasswordOptions, SealedBackup, SealedItem, SealedVault,
    Totp, UnlockedVault, ATTACHMENT_CHUNK_SIZE,
};

const PASSWORD: &str = "performance-password";

fn main() -> vault_core::Result<()> {
    let mut rounds = Vec::new();
    for round in 1..=3 {
        eprintln!("round {round}");
        rounds.push(one_round()?);
    }
    println!("scenario	median_ns	round1_ns	round2_ns	round3_ns");
    let names: Vec<&str> = rounds[0].iter().map(|(name, _)| name.as_str()).collect();
    for (index, name) in names.iter().enumerate() {
        let mut values: Vec<f64> = rounds.iter().map(|round| round[index].1).collect();
        values.sort_by(|left, right| left.partial_cmp(right).unwrap());
        println!(
            "{name}	{:.1}	{:.1}	{:.1}	{:.1}",
            values[1], rounds[0][index].1, rounds[1][index].1, rounds[2][index].1
        );
    }
    Ok(())
}

fn one_round() -> vault_core::Result<Vec<(String, f64)>> {
    let (mut vault, _) = UnlockedVault::create(PASSWORD)?;
    for index in 0..10_000 {
        vault.create_item(ItemDraft::new(format!("n{index}"), ItemData::SecureNote))?;
    }
    let last = vault.sealed_items().last().unwrap().item_id();
    let replacement = ItemDraft::new("replacement", ItemData::SecureNote);
    let header = vault.header();
    let records = vault.sealed_items().to_vec();
    let header_bytes = header.to_bytes()?;
    let record_bytes: Vec<Vec<u8>> = records
        .iter()
        .map(SealedItem::to_bytes)
        .collect::<Result<_, _>>()?;
    let totp = Totp::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    let short = PasswordOptions::default();
    let long = PasswordOptions {
        length: 128,
        ..PasswordOptions::default()
    };
    let mut rows = Vec::new();

    rows.push(measure("encode_last_10000", 100_000, || {
        black_box(vault.export_item(last)?.to_bytes()?.len());
        Ok(())
    })?);
    rows.push(measure("read_last_10000", 10_000, || {
        black_box(vault.get_item(last)?.title.len());
        Ok(())
    })?);
    rows.push(measure("update_last_10000", 3_000, || {
        black_box(vault.update_item(last, replacement.clone())?.revision);
        Ok(())
    })?);
    rows.push(measure("search_10000", 10, || {
        black_box(vault.search("zzzz-not-present")?.len());
        Ok(())
    })?);
    rows.push(measure("header_10000", 100_000, || {
        black_box(vault.header().vault_id());
        Ok(())
    })?);
    rows.push(measure("backup_10000", 10, || {
        black_box(vault.backup()?.to_bytes()?.len());
        Ok(())
    })?);
    rows.push(measure("import_10000", 3, || {
        let mut opened = UnlockedVault::unlock(&header, PASSWORD)?;
        for record in &records {
            opened.import_item(record, None)?;
        }
        black_box(opened.sealed_items().len());
        Ok(())
    })?);
    rows.push(measure("encode_10000", 10, || {
        let mut total = vault.header().to_bytes()?.len();
        for item in vault.sealed_items() {
            total += item.to_bytes()?.len();
        }
        black_box(total);
        Ok(())
    })?);
    rows.push(measure("parse_10000", 10, || {
        black_box(SealedVault::from_bytes(&header_bytes)?.vault_id());
        for record in &record_bytes {
            black_box(SealedItem::from_bytes(record)?.item_id());
        }
        Ok(())
    })?);
    rows.push(measure("password_24", 10_000, || {
        black_box(generate_password(&short)?.len());
        Ok(())
    })?);
    rows.push(measure("password_128", 5_000, || {
        black_box(generate_password(&long)?.len());
        Ok(())
    })?);
    rows.push(measure("totp", 100_000, || {
        black_box(totp.code_at(59)?.len());
        Ok(())
    })?);
    rows.push(measure("attachment_1mib", 30, || {
        let mut writer = vault.begin_attachment(last, 1, 1024 * 1024)?;
        let chunk = vec![7u8; ATTACHMENT_CHUNK_SIZE];
        for _ in 0..(1024 * 1024 / ATTACHMENT_CHUNK_SIZE) {
            black_box(writer.encrypt_chunk(&chunk)?);
        }
        black_box(writer.finish()?.attachment_id());
        Ok(())
    })?);
    rows.push(measure("kdf_unlock", 10, || {
        black_box(UnlockedVault::unlock(&header, PASSWORD)?.vault_id());
        Ok(())
    })?);
    let _ = SealedBackup::from_bytes(&vault.backup()?.to_bytes()?);
    Ok(rows)
}

fn measure(
    name: &str,
    iterations: u32,
    mut body: impl FnMut() -> vault_core::Result<()>,
) -> vault_core::Result<(String, f64)> {
    body()?;
    let started = Instant::now();
    for _ in 0..iterations {
        body()?;
    }
    let nanos = started.elapsed().as_nanos() as f64 / f64::from(iterations);
    eprintln!("{name} {nanos:.1} ns");
    Ok((name.to_owned(), nanos))
}
