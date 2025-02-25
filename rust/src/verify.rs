use digest::Digest;
use pkcs8::AssociatedOid;
use rasn::prelude::*;
use rasn_cms::{
    AlgorithmIdentifier, Attribute, Certificate as X509Certificate, ContentInfo,
    ExtendedCertificate, OtherCertificateFormat, SignedData, SignerInfo,
};
use rasn_pkix::{attribute_certificate::AttributeCertificate, AttributeValue};
use rsa::pkcs1::DecodeRsaPublicKey;
use std::fmt::Display;
use thiserror::Error;

#[derive(Debug)]
pub enum UnexpectedCertificateFormat {
    ExtendedCertificate(Box<ExtendedCertificate>),
    V2AttributeCertificate(Box<AttributeCertificate>),
    OtherCertificateFormat(OtherCertificateFormat),
}

impl Display for UnexpectedCertificateFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnexpectedCertificateFormat::ExtendedCertificate(cert) => {
                write!(f, "Unexpected ExtendedCertificate found: {:?}", cert)
            }
            UnexpectedCertificateFormat::V2AttributeCertificate(cert) => {
                write!(f, "Unexpected V2AttributeCertificate found: {:?}", cert)
            }
            UnexpectedCertificateFormat::OtherCertificateFormat(cert) => {
                write!(f, "Unexpected OtherCertificateFormat found: {:?}", cert)
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum SodSignedDataLoadingError {
    #[error("Failed to decode SOD DER: {0}")]
    FailedToDecodeSodDer(rasn::error::DecodeError),
    #[error("Failed to decode SignedData from SOD ContentInfo: {0}")]
    FailedToDecodeSignedDataFromContentInfo(rasn::error::DecodeError),
    #[error("Expected SignedData content type (OID: 1.2.840.113549.1.7.2). Got OID: {0}")]
    ExpectedSignedDataContentType(ObjectIdentifier),
}

#[derive(Debug, Error)]
pub enum GetX509CertIssuerError {
    #[error(
        "Failed to extract country name. Error: {utf8_error}, attribute value: {attribute_value:?}"
    )]
    FailedToExtractCountryName {
        utf8_error: std::string::FromUtf8Error,
        attribute_value: rasn::types::Any,
    },
    #[error("No country name found in certificate")]
    NoCountryNameFound,
}

#[derive(Debug, Error)]
pub enum ExtractCertificateFromSignedDataError {
    #[error("Expected exactly one certificate in the SignedData, found {0}")]
    InvalidCertificateCount(usize),
    #[error("Expected exactly one certificate in the SignedData, found {0}")]
    UnexpectedCertificateFormat(UnexpectedCertificateFormat),
    #[error("SignedData has no certificates")]
    NoCertificatesFound,
}

#[derive(Debug, Error)]
pub enum GetSodIssuerCountryError {
    #[error(transparent)]
    SodSignedDataLoadingError(#[from] SodSignedDataLoadingError),
    #[error(transparent)]
    ExtractCertificateFromSignedDataError(#[from] ExtractCertificateFromSignedDataError),
    #[error(transparent)]
    GetX509CertIssuerError(#[from] GetX509CertIssuerError),
}

#[derive(Debug, Error)]
pub enum VerifyX509SignatureTrustChainError {
    #[error("Unsupported signature algorithm for X509 certificate. OID: {0}")]
    UnsupportedSignatureAlgorithmForX509Cert(ObjectIdentifier),
    #[error("Failed to encode TBSCertificate: {0}")]
    FailedToEncodeTbsCertificate(rasn::error::EncodeError),
    #[error(transparent)]
    RsaSignatureVerificationFailed(#[from] rsa::Error),
}

#[derive(Debug, Error)]
pub enum VerifyCscaSignatureError {
    #[error(transparent)]
    ExtractCertificateFromSignedDataError(#[from] ExtractCertificateFromSignedDataError),
    #[error("Could not establish trust chain for SignedData SOD DS from CSCA: {0}")]
    CouldNotEstablishTrustChainForSignedDataSOD(VerifyX509SignatureTrustChainError),
}

#[derive(Debug, Error)]
pub enum ExtractMessageDigestError {
    #[error("Expected exactly one value in message digest attribute, found: {0:?}")]
    ExpectedOneValueInMessageDigestAttribute(SetOf<AttributeValue>),
    #[error("No message digest attribute found in signed attributes: {0:?}")]
    NoMessageDigestAttributeFound(SetOf<Attribute>),
    #[error("Failed to decode MessageDigest for LDS object: {0}")]
    FailedToDecodeMessageDigest(rasn::error::DecodeError),
}

#[derive(Debug, Error)]
pub enum ExtractSignerInfoError {
    #[error("Expected exactly one SignerInfo, found {0}")]
    InvalidSignerInfoCount(usize),
}

#[derive(Debug, Error)]
pub enum VerifyDsSignatureError {
    #[error(transparent)]
    ExtractSignerInfoError(#[from] ExtractSignerInfoError),
    #[error("Unsupported digest algorithm for DS signature. OID: {0}")]
    UnsupportedDigestAlgorithmForDsRsaSignature(ObjectIdentifier),
    #[error("Unsupported signature algorithm for DS signature. OID: {0}")]
    UnsupportedDsSignatureAlgorithm(ObjectIdentifier),
    #[error(transparent)]
    ExtractCertificateFromSignedDataError(#[from] ExtractCertificateFromSignedDataError),
    #[error("No signed attributes found in signer info for DS signature")]
    NoSignedAttributesFoundForDsSignature,
    #[error("Failed to encode signed attributes: {0}")]
    FailedToEncodeSignedAttributes(rasn::error::EncodeError),
    #[error("Could not parse rsa pubkey")]
    CouldNotParseRsaPubKey(rsa::pkcs1::Error),
    #[error(transparent)]
    DsRsaSignatureVerificationFailed(#[from] rsa::Error),
}

#[derive(Debug, Error)]
pub enum VerifyLdsObjectHashError {
    #[error(transparent)]
    ExtractSignerInfoError(#[from] ExtractSignerInfoError),
    #[error("No signed attributes found in signer info for while searching for LDS object hash")]
    NoSignedAttributesFoundForLdsObjectHash,
    #[error(transparent)]
    ExtractMessageDigestError(#[from] ExtractMessageDigestError),
    #[error("Unsupported digest algorithm for LDS object. OID: {0}")]
    UnsupportedDigestAlgorithmForLdsObject(ObjectIdentifier),
    #[error("Expected content in SignedData for verifying LDS object hash: {0:?}")]
    ExpectedContentInSignedData(SignedData),
    #[error("Unexpected LDS object hash. Expected: {expected:?}, got: {actual:?}")]
    UnexpectedLdsObjectHash { expected: Vec<u8>, actual: Vec<u8> },
}

#[derive(Debug, Error)]
pub enum VerifyDgHashError {
    #[error("Object is not LDS Security Object. OID: {0}")]
    ObjectIsNotLdsSecurityObject(ObjectIdentifier),
    #[error("No encapsulated content in SignedData for verifying DG hash")]
    NoEncapsulatedContentInSignedDataForDgHash,
    #[error("Failed to decode LDS Security Object: {0}")]
    FailedToDecodeLdsSecurityObject(rasn::error::DecodeError),
    #[error("No hash found for Data Group {0}")]
    NoHashFoundForDG(i32),
    #[error("Unsupported digest algorithm for Data Group. OID: {0}")]
    UnsupportedDigestAlgorithmForDG(ObjectIdentifier),
    #[error("Hash mismatch for DG{data_group_number}. Expected: {expected:?}, got: {actual:?}")]
    DGHashMismatch {
        data_group_number: i32,
        expected: Vec<u8>,
        actual: Vec<u8>,
    },
}

#[derive(Debug, Error)]
pub enum PassportVerificationError {
    #[error(transparent)]
    SodSignedDataLoadingError(#[from] SodSignedDataLoadingError),
    #[error("Failed to decode CSCA certificate: {0}")]
    FailedToDecodeCscaCertificate(rasn::error::DecodeError),
    #[error(transparent)]
    VerifyCscaSignatureError(#[from] VerifyCscaSignatureError),
    #[error(transparent)]
    VerifyDsSignatureError(#[from] VerifyDsSignatureError),
    #[error(transparent)]
    VerifyLdsObjectHashError(#[from] VerifyLdsObjectHashError),
    #[error(transparent)]
    VerifyDgHashError(#[from] VerifyDgHashError),
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(application, 23))]
pub struct SOD {
    pub content_info: ContentInfo,
}

// See: https://www.icao.int/publications/documents/9303_p10_cons_en.pdf#page=45, Section 4.6.2.1
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct LdsSecurityObject {
    pub version: i32,
    pub hash_algorithm: AlgorithmIdentifier,
    pub data_group_hash_values: SequenceOf<DataGroupHash>,
    pub lds_version_info: Option<LdsVersionInfo>,
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct DataGroupHash {
    pub data_group_number: i32,
    pub data_group_hash_value: OctetString,
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct LdsVersionInfo {
    pub lds_version: PrintableString,
    pub unicode_version: PrintableString,
}

pub fn load_signed_data_from_sod_bytes(
    sod_data: &[u8],
) -> Result<SignedData, SodSignedDataLoadingError> {
    let sod: SOD =
        rasn::der::decode(sod_data).map_err(SodSignedDataLoadingError::FailedToDecodeSodDer)?;
    let content_info = sod.content_info;
    if content_info.content_type != rasn_cms::CONTENT_SIGNED_DATA {
        // OID: 1.2.840.113549.1.7.2
        return Err(SodSignedDataLoadingError::ExpectedSignedDataContentType(
            content_info.content_type,
        ));
    }
    let signed_data = rasn::der::decode::<SignedData>(content_info.content.as_bytes())
        .map_err(SodSignedDataLoadingError::FailedToDecodeSignedDataFromContentInfo)?;
    Ok(signed_data)
}

fn get_x509_cert_issuer_country(cert: &X509Certificate) -> Result<String, GetX509CertIssuerError> {
    let rasn_cms::Name::RdnSequence(vec) = &cert.tbs_certificate.issuer;
    for rdn in vec {
        for attr in rdn.to_vec() {
            if attr.r#type == Oid::JOINT_ISO_ITU_T_DS_ATTRIBUTE_TYPE_COUNTRY_NAME {
                // OID: 2.5.4.6
                let attribute_value: &rasn::types::Any = &attr.value;
                let country_name =
                    String::from_utf8(attribute_value.as_bytes().to_vec()).map_err(|e| {
                        GetX509CertIssuerError::FailedToExtractCountryName {
                            utf8_error: e,
                            attribute_value: attribute_value.clone(),
                        }
                    })?;
                return Ok(country_name);
            }
        }
    }
    Err(GetX509CertIssuerError::NoCountryNameFound)
}

fn extract_single_certificate_from_signed_data(
    signed_data: &SignedData,
) -> Result<Box<X509Certificate>, ExtractCertificateFromSignedDataError> {
    if let Some(all_sod_certs) = &signed_data.certificates {
        if all_sod_certs.len() != 1 {
            return Err(
                ExtractCertificateFromSignedDataError::InvalidCertificateCount(all_sod_certs.len()),
            );
        }
        match all_sod_certs.to_vec()[0].clone() {
            rasn_cms::CertificateChoices::Certificate(cert) => Ok(cert),
            rasn_cms::CertificateChoices::ExtendedCertificate(extended_certificate) => Err(
                ExtractCertificateFromSignedDataError::UnexpectedCertificateFormat(
                    UnexpectedCertificateFormat::ExtendedCertificate(extended_certificate),
                ),
            ),
            rasn_cms::CertificateChoices::V2AttributeCertificate(attribute_certificate) => Err(
                ExtractCertificateFromSignedDataError::UnexpectedCertificateFormat(
                    UnexpectedCertificateFormat::V2AttributeCertificate(attribute_certificate),
                ),
            ),
            rasn_cms::CertificateChoices::Other(other_certificate_format) => Err(
                ExtractCertificateFromSignedDataError::UnexpectedCertificateFormat(
                    UnexpectedCertificateFormat::OtherCertificateFormat(other_certificate_format),
                ),
            ),
        }
    } else {
        Err(ExtractCertificateFromSignedDataError::NoCertificatesFound)
    }
}

pub fn get_sod_issuer_country(sod_data_bytes: &[u8]) -> Result<String, GetSodIssuerCountryError> {
    let signed_data = load_signed_data_from_sod_bytes(sod_data_bytes)?;
    let sod_cert = extract_single_certificate_from_signed_data(&signed_data)?;
    Ok(get_x509_cert_issuer_country(&sod_cert)?)
}

pub fn verify_csca_signature(
    csca_cert: &X509Certificate,
    signed_data: &SignedData,
) -> Result<(), VerifyCscaSignatureError> {
    let sod_cert = extract_single_certificate_from_signed_data(signed_data)?;
    verify_x509_signature_trust_chain(csca_cert, &sod_cert)
        .map_err(VerifyCscaSignatureError::CouldNotEstablishTrustChainForSignedDataSOD)
}

fn rsa_verify<D>(
    public_key_bytes: &[u8],
    signature_bytes: &[u8],
    data: &[u8],
) -> Result<(), rsa::Error>
where
    D: Digest + AssociatedOid,
{
    let public_key = rsa::RsaPublicKey::from_pkcs1_der(public_key_bytes)?;
    let padding = rsa::Pkcs1v15Sign::new::<D>();
    public_key.verify(padding, D::digest(data).as_ref(), signature_bytes)
}

// Signature Algorithm OIDs
// See: https://github.com/rusticata/oid-registry/blob/cd92ffa605e1c73f3cf0ec2503b98d08eba72293/assets/oid_db.txt
const OID_PKCS1_SHA1WITHRSA: &'_ Oid = Oid::const_new(&[1, 2, 840, 113549, 1, 1, 5]); // same as Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS1_SHA1_RSA
const OID_SHA1_WITH_RSA: &'_ Oid = Oid::const_new(&[1, 3, 14, 3, 2, 29]);
const OID_PKCS1_SHA256WITHRSA: &'_ Oid = Oid::const_new(&[1, 2, 840, 113549, 1, 1, 11]);
const OID_PKCS1_SHA384WITHRSA: &'_ Oid = Oid::const_new(&[1, 2, 840, 113549, 1, 1, 12]);
const OID_PKCS1_SHA512WITHRSA: &'_ Oid = Oid::const_new(&[1, 2, 840, 113549, 1, 1, 13]);

fn verify_x509_signature_trust_chain(
    authority_certificate: &X509Certificate,
    subject_certificate: &X509Certificate,
) -> Result<(), VerifyX509SignatureTrustChainError> {
    let authority_public_key_bytes = &authority_certificate
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .to_bitvec()
        .into_vec();

    let signature_bytes = subject_certificate.signature_value.to_bitvec().into_vec();

    let tbs_certificate_der_bytes = rasn::der::encode(&subject_certificate.tbs_certificate)
        .map_err(VerifyX509SignatureTrustChainError::FailedToEncodeTbsCertificate)?;

    let signature_algorithm_oid = &subject_certificate.signature_algorithm.algorithm;
    // See: https://github.com/rusticata/x509-parser/blob/7b919a821341246883b9f41724727b8c413079f0/src/verify.rs#L31-L55
    if signature_algorithm_oid == OID_PKCS1_SHA1WITHRSA
        || signature_algorithm_oid == OID_SHA1_WITH_RSA
    {
        Ok(rsa_verify::<sha1::Sha1>(
            authority_public_key_bytes,
            &signature_bytes,
            &tbs_certificate_der_bytes,
        )?)
    } else if signature_algorithm_oid == OID_PKCS1_SHA256WITHRSA {
        Ok(rsa_verify::<sha2::Sha256>(
            authority_public_key_bytes,
            &signature_bytes,
            &tbs_certificate_der_bytes,
        )?)
    } else if signature_algorithm_oid == OID_PKCS1_SHA384WITHRSA {
        Ok(rsa_verify::<sha2::Sha384>(
            authority_public_key_bytes,
            &signature_bytes,
            &tbs_certificate_der_bytes,
        )?)
    } else if signature_algorithm_oid == OID_PKCS1_SHA512WITHRSA {
        Ok(rsa_verify::<sha2::Sha512>(
            authority_public_key_bytes,
            &signature_bytes,
            &tbs_certificate_der_bytes,
        )?)
    }
    // TODO: ECDSA, ED25519
    else {
        Err(
            VerifyX509SignatureTrustChainError::UnsupportedSignatureAlgorithmForX509Cert(
                signature_algorithm_oid.clone(),
            ),
        )
    }
}

fn extract_message_digest_value_from_signed_attrs(
    signed_attrs: &SetOf<Attribute>,
) -> Result<rasn::types::OctetString, ExtractMessageDigestError> {
    for attr in signed_attrs.to_vec() {
        if attr.r#type == Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS9_MESSAGE_DIGEST {
            // OID: 1.2.840.113549.1.9.4
            if attr.values.len() != 1 {
                return Err(
                    ExtractMessageDigestError::ExpectedOneValueInMessageDigestAttribute(
                        attr.values.clone(),
                    ),
                );
            }
            let message_digest_bytes = attr.values.to_vec()[0].as_bytes();
            return rasn::der::decode::<OctetString>(message_digest_bytes)
                .map_err(ExtractMessageDigestError::FailedToDecodeMessageDigest);
        }
    }
    Err(ExtractMessageDigestError::NoMessageDigestAttributeFound(
        signed_attrs.clone(),
    ))
}

fn extract_signer_info(signed_data: &SignedData) -> Result<&SignerInfo, ExtractSignerInfoError> {
    if signed_data.signer_infos.len() != 1 {
        return Err(ExtractSignerInfoError::InvalidSignerInfoCount(
            signed_data.signer_infos.len(),
        ));
    }
    Ok(signed_data.signer_infos.to_vec()[0])
}

pub fn verify_ds_signature(signed_data: &SignedData) -> Result<(), VerifyDsSignatureError> {
    let ds_cert = extract_single_certificate_from_signed_data(signed_data)?;
    let public_key_bytes = ds_cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .to_bitvec()
        .into_vec();

    let signer_info = extract_signer_info(signed_data)?;
    let signature_bytes: &[u8] = signer_info.signature.as_ref();
    let signed_attrs = signer_info
        .signed_attrs
        .as_ref()
        .ok_or(VerifyDsSignatureError::NoSignedAttributesFoundForDsSignature)?;
    let signed_attrs_der_bytes = rasn::der::encode(signed_attrs)
        .map_err(VerifyDsSignatureError::FailedToEncodeSignedAttributes)?;

    let signer_algo_oid = &signer_info.signature_algorithm.algorithm;
    let digest_algo_oid = &signer_info.digest_algorithm.algorithm;

    if signer_algo_oid == Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS1_RSA {
        // OID: 1.2.840.113549.1.1.1
        if digest_algo_oid == Oid::ISO_IDENTIFIED_ORGANISATION_OIW_SECSIG_ALGORITHM_SHA1 {
            // OID: 1.3.14.3.2.26
            Ok(rsa_verify::<sha1::Sha1>(
                &public_key_bytes,
                signature_bytes,
                &signed_attrs_der_bytes,
            )?)
        } else if digest_algo_oid
            == Oid::JOINT_ISO_ITU_T_COUNTRY_US_ORGANIZATION_GOV_CSOR_NIST_ALGORITHMS_HASH_SHA256
        {
            // OID: 2.16.840.1.101.3.4.2.1
            Ok(rsa_verify::<sha2::Sha256>(
                &public_key_bytes,
                signature_bytes,
                &signed_attrs_der_bytes,
            )?)
        } else if digest_algo_oid
            == Oid::JOINT_ISO_ITU_T_COUNTRY_US_ORGANIZATION_GOV_CSOR_NIST_ALGORITHMS_HASH_SHA384
        {
            // OID: 2.16.840.1.101.3.4.2.2
            Ok(rsa_verify::<sha2::Sha384>(
                &public_key_bytes,
                signature_bytes,
                &signed_attrs_der_bytes,
            )?)
        } else if digest_algo_oid
            == Oid::JOINT_ISO_ITU_T_COUNTRY_US_ORGANIZATION_GOV_CSOR_NIST_ALGORITHMS_HASH_SHA512
        {
            // OID: 2.16.840.1.101.3.4.2.3
            Ok(rsa_verify::<sha2::Sha512>(
                &public_key_bytes,
                signature_bytes,
                &signed_attrs_der_bytes,
            )?)
        } else {
            Err(
                VerifyDsSignatureError::UnsupportedDigestAlgorithmForDsRsaSignature(
                    digest_algo_oid.clone(),
                ),
            )
        }
    }
    // TODO: Support ECDSA
    else {
        Err(VerifyDsSignatureError::UnsupportedDsSignatureAlgorithm(
            signer_algo_oid.clone(),
        ))
    }
}

pub fn verify_lds_object_hash(signed_data: &SignedData) -> Result<(), VerifyLdsObjectHashError> {
    let signer_info = extract_signer_info(signed_data)?;
    let signed_attrs = signer_info
        .signed_attrs
        .as_ref()
        .ok_or(VerifyLdsObjectHashError::NoSignedAttributesFoundForLdsObjectHash)?;
    let expected_message_digest = extract_message_digest_value_from_signed_attrs(signed_attrs)?;
    let lds_obj_bytes: &[u8] = signed_data
        .encap_content_info
        .content
        .as_ref()
        .ok_or_else(|| VerifyLdsObjectHashError::ExpectedContentInSignedData(signed_data.clone()))?
        .as_ref();
    let digest_algo_oid = &signer_info.digest_algorithm.algorithm;
    let actual_digest: Vec<u8> =
        if digest_algo_oid == Oid::ISO_IDENTIFIED_ORGANISATION_OIW_SECSIG_ALGORITHM_SHA1 {
            // OID: 1.3.14.3.2.26
            sha1::Sha1::digest(lds_obj_bytes).to_vec()
        } else if digest_algo_oid
            == Oid::JOINT_ISO_ITU_T_COUNTRY_US_ORGANIZATION_GOV_CSOR_NIST_ALGORITHMS_HASH_SHA256
        {
            // OID: 2.16.840.1.101.3.4.2.1
            sha2::Sha256::digest(lds_obj_bytes).to_vec()
        } else if digest_algo_oid
            == Oid::JOINT_ISO_ITU_T_COUNTRY_US_ORGANIZATION_GOV_CSOR_NIST_ALGORITHMS_HASH_SHA384
        {
            // OID: 2.16.840.1.101.3.4.2.2
            sha2::Sha384::digest(lds_obj_bytes).to_vec()
        } else if digest_algo_oid
            == Oid::JOINT_ISO_ITU_T_COUNTRY_US_ORGANIZATION_GOV_CSOR_NIST_ALGORITHMS_HASH_SHA512
        {
            // OID: 2.16.840.1.101.3.4.2.3
            sha2::Sha512::digest(lds_obj_bytes).to_vec()
        } else if digest_algo_oid == Oid::const_new(&[2, 16, 840, 1, 101, 3, 4, 2, 4]) {
            // OID: 2.16.840.1.101.3.4.2.4
            sha2::Sha224::digest(lds_obj_bytes).to_vec()
        } else if digest_algo_oid
            == Oid::JOINT_ISO_ITU_T_COUNTRY_US_ORGANIZATION_GOV_CSOR_NIST_ALGORITHMS_HASH_SHA512_224
        {
            // OID: 2.16.840.1.101.3.4.2.5
            sha2::Sha512_224::digest(lds_obj_bytes).to_vec()
        } else if digest_algo_oid
            == Oid::JOINT_ISO_ITU_T_COUNTRY_US_ORGANIZATION_GOV_CSOR_NIST_ALGORITHMS_HASH_SHA512_256
        {
            // OID: 2.16.840.1.101.3.4.2.6
            sha2::Sha512_256::digest(lds_obj_bytes).to_vec()
        } else {
            return Err(
                VerifyLdsObjectHashError::UnsupportedDigestAlgorithmForLdsObject(
                    digest_algo_oid.clone(),
                ),
            );
        };
    if expected_message_digest == actual_digest {
        Ok(())
    } else {
        Err(VerifyLdsObjectHashError::UnexpectedLdsObjectHash {
            expected: expected_message_digest.as_ref().to_vec(),
            actual: actual_digest,
        })
    }
}

const OID_LDS_SECURITY_OBJECT: &'_ Oid = Oid::const_new(&[2, 23, 136, 1, 1, 1]);
const OID_SHA256: &'_ Oid = Oid::const_new(&[2, 16, 840, 1, 101, 3, 4, 2, 1]);
const OID_SHA384: &'_ Oid = Oid::const_new(&[2, 16, 840, 1, 101, 3, 4, 2, 2]);
const OID_SHA512: &'_ Oid = Oid::const_new(&[2, 16, 840, 1, 101, 3, 4, 2, 3]);
const OID_SHA224: &'_ Oid = Oid::const_new(&[2, 16, 840, 1, 101, 3, 4, 2, 4]);
const OID_SHA512_224: &'_ Oid = Oid::const_new(&[2, 16, 840, 1, 101, 3, 4, 2, 5]);
const OID_SHA512_256: &'_ Oid = Oid::const_new(&[2, 16, 840, 1, 101, 3, 4, 2, 6]);

pub fn verify_dg_hash(
    signed_data: &SignedData,
    dg_data: &[u8],
    dg_num: i32,
) -> Result<(), VerifyDgHashError> {
    let encap_content_info = &signed_data.encap_content_info;
    if encap_content_info.content_type != *OID_LDS_SECURITY_OBJECT {
        return Err(VerifyDgHashError::ObjectIsNotLdsSecurityObject(
            encap_content_info.content_type.clone(),
        ));
    }

    let lds_obj: LdsSecurityObject = rasn::der::decode(
        encap_content_info
            .content
            .as_ref()
            .ok_or(VerifyDgHashError::NoEncapsulatedContentInSignedDataForDgHash)?
            .as_ref(),
    )
    .map_err(VerifyDgHashError::FailedToDecodeLdsSecurityObject)?;

    let dg_hash = lds_obj
        .data_group_hash_values
        .iter()
        .find(|h| h.data_group_number == dg_num)
        .ok_or(VerifyDgHashError::NoHashFoundForDG(dg_num))?
        .data_group_hash_value
        .as_ref();

    let hash_algo_oid = &lds_obj.hash_algorithm.algorithm;
    let actual_hash: Vec<u8> = if hash_algo_oid == OID_SHA256 {
        sha2::Sha256::digest(dg_data).to_vec()
    } else if hash_algo_oid == OID_SHA384 {
        sha2::Sha384::digest(dg_data).to_vec()
    } else if hash_algo_oid == OID_SHA512 {
        sha2::Sha512::digest(dg_data).to_vec()
    } else if hash_algo_oid == OID_SHA224 {
        sha2::Sha224::digest(dg_data).to_vec()
    } else if hash_algo_oid == OID_SHA512_224 {
        sha2::Sha512_224::digest(dg_data).to_vec()
    } else if hash_algo_oid == OID_SHA512_256 {
        sha2::Sha512_256::digest(dg_data).to_vec()
    } else {
        return Err(VerifyDgHashError::UnsupportedDigestAlgorithmForDG(
            hash_algo_oid.clone(),
        ));
    };

    if dg_hash == actual_hash {
        Ok(())
    } else {
        Err(VerifyDgHashError::DGHashMismatch {
            data_group_number: dg_num,
            expected: dg_hash.to_vec(),
            actual: actual_hash,
        })
    }
}

pub fn verify_sod_bytes(
    sod_data_bytes: &[u8],
    csca_cert_bytes: &[u8],
    data_group_bytes: &[u8],
    data_group_number: i32,
) -> Result<(), PassportVerificationError> {
    let signed_data = load_signed_data_from_sod_bytes(sod_data_bytes)?;
    let csca_cert: X509Certificate = rasn::der::decode(csca_cert_bytes)
        .map_err(PassportVerificationError::FailedToDecodeCscaCertificate)?;

    verify_csca_signature(&csca_cert, &signed_data)?;
    verify_ds_signature(&signed_data)?;
    verify_lds_object_hash(&signed_data)?;
    verify_dg_hash(&signed_data, data_group_bytes, data_group_number)?;

    Ok(())
}
