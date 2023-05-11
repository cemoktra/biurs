use std::{path::PathBuf, time::SystemTime};

pub struct StatusRequest {
    pub file: PathBuf,
    pub content_hash: Vec<u8>,
    pub modified_at: SystemTime,
}

pub enum StatusResponse {
    Missing,
    Mismatch(Mismatch),
    Match,
}

pub struct Mismatch {
    pub server_modified_at: SystemTime,
    pub client_modified_at: SystemTime,
}

impl TryFrom<crate::proto::biurs_v1::Mismatch> for Mismatch {
    type Error = crate::types::TypeError;

    fn try_from(value: crate::proto::biurs_v1::Mismatch) -> Result<Self, Self::Error> {
        let server_modified_at =
            value
                .server_modified_at
                .ok_or(crate::types::TypeError::MandatoryFieldMissing(
                    "Metadata",
                    "server_modified_at",
                ))?;

        let client_modified_at =
            value
                .client_modified_at
                .ok_or(crate::types::TypeError::MandatoryFieldMissing(
                    "Metadata",
                    "client_modified_at",
                ))?;

        Ok(Self {
            server_modified_at: server_modified_at.try_into()?,
            client_modified_at: client_modified_at.try_into()?,
        })
    }
}

impl From<Mismatch> for crate::proto::biurs_v1::Mismatch {
    fn from(value: Mismatch) -> Self {
        Self {
            server_modified_at: Some(value.server_modified_at.into()),
            client_modified_at: Some(value.client_modified_at.into()),
        }
    }
}

impl TryFrom<crate::proto::biurs_v1::StatusRequest> for StatusRequest {
    type Error = crate::types::TypeError;

    fn try_from(value: crate::proto::biurs_v1::StatusRequest) -> Result<Self, Self::Error> {
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

impl TryFrom<crate::proto::biurs_v1::StatusResponse> for StatusResponse {
    type Error = crate::types::TypeError;

    fn try_from(value: crate::proto::biurs_v1::StatusResponse) -> Result<Self, Self::Error> {
        let status = value
            .status
            .ok_or(crate::types::TypeError::MandatoryFieldMissing(
                "StatusResponse",
                "status",
            ))?;

        match status {
            crate::proto::biurs_v1::status_response::Status::Missing(_) => {
                Ok(StatusResponse::Missing)
            }
            crate::proto::biurs_v1::status_response::Status::Mismatch(mismatch) => {
                Ok(StatusResponse::Mismatch(mismatch.try_into()?))
            }
            crate::proto::biurs_v1::status_response::Status::Match(_) => Ok(StatusResponse::Match),
        }
    }
}

impl From<StatusRequest> for crate::proto::biurs_v1::StatusRequest {
    fn from(value: StatusRequest) -> Self {
        Self {
            file: value.file.display().to_string(),
            content_hash: value.content_hash,
            modified_at: Some(value.modified_at.into()),
        }
    }
}

impl From<StatusResponse> for crate::proto::biurs_v1::StatusResponse {
    fn from(value: StatusResponse) -> Self {
        let status = match value {
            StatusResponse::Missing => crate::proto::biurs_v1::status_response::Status::Missing(()),
            StatusResponse::Mismatch(mismatch) => {
                crate::proto::biurs_v1::status_response::Status::Mismatch(mismatch.into())
            }
            StatusResponse::Match => crate::proto::biurs_v1::status_response::Status::Match(()),
        };

        Self {
            status: Some(status),
        }
    }
}
