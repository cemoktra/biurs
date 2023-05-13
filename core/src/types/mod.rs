use std::{path::PathBuf, time::SystemTime};

pub mod auth;
pub mod download;
pub mod list;
pub mod status;
pub mod upload;

#[derive(Debug, thiserror::Error)]
pub enum TypeError {
    #[error("the mandatory field '{1}' on '{0}' is missing")]
    MandatoryFieldMissing(&'static str, &'static str),
    #[error(transparent)]
    TimestampError(#[from] prost_types::TimestampError),
    #[error("Expected {1} bytes but found {0}")]
    WrongDataLength(usize, usize),
}

impl From<TypeError> for tonic::Status {
    fn from(value: TypeError) -> Self {
        match value {
            TypeError::MandatoryFieldMissing(_, _)
            | TypeError::TimestampError(_)
            | TypeError::WrongDataLength(_, _) => {
                tonic::Status::invalid_argument(value.to_string())
            }
        }
    }
}

#[derive(Clone)]
pub struct Metadata {
    pub file: PathBuf,
    pub content_hash: Vec<u8>,
    pub modified_at: SystemTime,
}

impl TryFrom<crate::proto::biurs_v1::Metadata> for Metadata {
    type Error = TypeError;

    fn try_from(value: crate::proto::biurs_v1::Metadata) -> Result<Self, Self::Error> {
        let modified_at =
            value
                .modified_at
                .ok_or(crate::types::TypeError::MandatoryFieldMissing(
                    "Metadata",
                    "modified_at",
                ))?;

        Ok(Self {
            file: value.file.into(),
            content_hash: value.content_hash,
            modified_at: modified_at.try_into()?,
        })
    }
}

impl From<Metadata> for crate::proto::biurs_v1::Metadata {
    fn from(value: Metadata) -> Self {
        Self {
            file: value.file.display().to_string(),
            content_hash: value.content_hash,
            modified_at: Some(value.modified_at.into()),
        }
    }
}
