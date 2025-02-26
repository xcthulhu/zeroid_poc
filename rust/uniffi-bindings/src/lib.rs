use base64::prelude::*;
use thiserror::Error;

uniffi::setup_scaffolding!();

#[derive(Debug, Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum VerifySODBytesError {
    #[error("Failed to decode SOD base64: {0}")]
    SODBase64DecodeError(base64::DecodeError),
    #[error("Failed to decode CSCA base64: {0}")]
    CSCABase64DecodeError(base64::DecodeError),
    #[error("Failed to decode data group base64: {0}")]
    DataGroupBase64DecodeError(base64::DecodeError),
    #[error(transparent)]
    PassportVerificationError(
        #[from] zeroid_rust_passport_verifier_core::PassportVerificationError,
    ),
}

#[uniffi::export]
fn verify_sod_base64(
    sod_data_base64: String,
    csca_cert_base64: String,
    data_group_base64: String,
    data_group_number: i32,
) -> Result<(), VerifySODBytesError> {
    let sod_data_bytes = BASE64_STANDARD
        .decode(&sod_data_base64)
        .map_err(VerifySODBytesError::SODBase64DecodeError)?;
    let csca_cert_bytes = BASE64_STANDARD
        .decode(&csca_cert_base64)
        .map_err(VerifySODBytesError::CSCABase64DecodeError)?;
    let data_group_bytes = BASE64_STANDARD
        .decode(&data_group_base64)
        .map_err(VerifySODBytesError::DataGroupBase64DecodeError)?;

    Ok(zeroid_rust_passport_verifier_core::verify_sod_bytes(
        &sod_data_bytes,
        &csca_cert_bytes,
        &data_group_bytes,
        data_group_number,
    )?)
}
