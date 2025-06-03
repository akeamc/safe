tonic::include_proto!("safe");

pub(crate) const FILE_DESCRIPTOR_SET: &[u8] =
    tonic::include_file_descriptor_set!("safe_descriptor");

impl From<RevocationReason> for rcgen::RevocationReason {
    fn from(reason: RevocationReason) -> Self {
        match reason {
            RevocationReason::Unspecified => rcgen::RevocationReason::Unspecified,
            RevocationReason::KeyCompromise => rcgen::RevocationReason::KeyCompromise,
            RevocationReason::CaCompromise => rcgen::RevocationReason::CaCompromise,
            RevocationReason::AffiliationChanged => rcgen::RevocationReason::AffiliationChanged,
            RevocationReason::Superseded => rcgen::RevocationReason::Superseded,
            RevocationReason::CessationOfOperation => rcgen::RevocationReason::CessationOfOperation,
            RevocationReason::CertificateHold => rcgen::RevocationReason::CertificateHold,
            RevocationReason::RemoveFromCrl => rcgen::RevocationReason::RemoveFromCrl,
            RevocationReason::PrivilegeWithdrawn => rcgen::RevocationReason::PrivilegeWithdrawn,
            RevocationReason::AaCompromise => rcgen::RevocationReason::AaCompromise,
        }
    }
}
