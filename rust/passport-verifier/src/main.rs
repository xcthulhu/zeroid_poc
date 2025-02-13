use std::{error::Error as StdError, path::PathBuf};

fn main() -> Result<(), Box<dyn StdError>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        eprintln!("Usage: {} <EF.SOD> <CSCA Cert> <dg-data> <dg-num>", args[0]);
        std::process::exit(1);
    }

    let sod_path: PathBuf = args[1].clone().into();
    let csca_path: PathBuf = args[2].clone().into();
    let data_group_path: PathBuf = args[3].clone().into();
    let data_group_number: i32 = args[4].parse()?;

    let sod_data_bytes = std::fs::read(sod_path)?;
    let csca_cert_bytes = std::fs::read(&csca_path)
        .map_err(|e| format!("Failed to read CSCA file '{}': {}", csca_path.display(), e))?;
    let data_group_bytes = std::fs::read(&data_group_path).map_err(|e| {
        format!(
            "Failed to read DG{data_group_number} file '{}': {}",
            data_group_path.display(),
            e
        )
    })?;

    zeroid_rust_passport_verifier_core::verify_sod_bytes(
        &sod_data_bytes,
        &csca_cert_bytes,
        &data_group_bytes,
        data_group_number,
    )?;
    println!("Passport verification successful");
    Ok(())
}
