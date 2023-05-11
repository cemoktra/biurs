pub enum UploadRequest {
    Meta(crate::types::Metadata),
    Data(Vec<u8>),
}

pub struct UploadFile {
    pub meta: crate::types::Metadata,
    pub data: Vec<u8>,
}

impl TryFrom<crate::proto::biurs_v1::UploadRequest> for UploadRequest {
    type Error = crate::types::TypeError;

    fn try_from(value: crate::proto::biurs_v1::UploadRequest) -> Result<Self, Self::Error> {
        let chunk = value
            .chunk
            .ok_or(crate::types::TypeError::MandatoryFieldMissing(
                "UploadRequest",
                "chunk",
            ))?;

        match chunk {
            crate::proto::biurs_v1::upload_request::Chunk::Meta(meta) => {
                Ok(UploadRequest::Meta(meta.try_into()?))
            }
            crate::proto::biurs_v1::upload_request::Chunk::Data(data) => {
                Ok(UploadRequest::Data(data))
            }
        }
    }
}

impl From<UploadRequest> for crate::proto::biurs_v1::UploadRequest {
    fn from(value: UploadRequest) -> Self {
        let chunk = match value {
            UploadRequest::Meta(meta) => {
                crate::proto::biurs_v1::upload_request::Chunk::Meta(meta.into())
            }
            UploadRequest::Data(data) => crate::proto::biurs_v1::upload_request::Chunk::Data(data),
        };

        Self { chunk: Some(chunk) }
    }
}
