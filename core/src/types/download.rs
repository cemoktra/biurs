use std::path::PathBuf;

pub struct DownloadRequest {
    pub file: PathBuf,
}

pub enum DownloadResponse {
    Meta(crate::types::Metadata),
    Data(Vec<u8>),
}

pub struct DownloadedFile {
    pub meta: crate::types::Metadata,
    pub data: Vec<u8>,
}

impl From<crate::proto::biurs_v1::DownloadRequest> for DownloadRequest {
    fn from(value: crate::proto::biurs_v1::DownloadRequest) -> Self {
        Self {
            file: value.file.into(),
        }
    }
}

impl TryFrom<crate::proto::biurs_v1::DownloadResponse> for DownloadResponse {
    type Error = crate::types::TypeError;

    fn try_from(value: crate::proto::biurs_v1::DownloadResponse) -> Result<Self, Self::Error> {
        let chunk = value
            .chunk
            .ok_or(crate::types::TypeError::MandatoryFieldMissing(
                "DownloadResponse",
                "chunk",
            ))?;

        match chunk {
            crate::proto::biurs_v1::download_response::Chunk::Meta(meta) => {
                Ok(DownloadResponse::Meta(meta.try_into()?))
            }
            crate::proto::biurs_v1::download_response::Chunk::Data(data) => {
                Ok(DownloadResponse::Data(data))
            }
        }
    }
}

impl From<DownloadRequest> for crate::proto::biurs_v1::DownloadRequest {
    fn from(value: DownloadRequest) -> Self {
        Self {
            file: value.file.display().to_string(),
        }
    }
}

impl From<DownloadResponse> for crate::proto::biurs_v1::DownloadResponse {
    fn from(value: DownloadResponse) -> Self {
        let chunk = match value {
            DownloadResponse::Meta(meta) => {
                crate::proto::biurs_v1::download_response::Chunk::Meta(meta.into())
            }
            DownloadResponse::Data(data) => {
                crate::proto::biurs_v1::download_response::Chunk::Data(data)
            }
        };

        Self { chunk: Some(chunk) }
    }
}
