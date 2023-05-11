#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error(transparent)]
    TonicStatus(#[from] tonic::Status),
    #[error(transparent)]
    Transport(#[from] tonic::transport::Error),
    #[error(transparent)]
    Type(#[from] crate::types::TypeError),
    #[error("Expected message")]
    MessageExpected,
    #[error("Unexpected message type")]
    UnexpectedMessageType,
}

#[async_trait::async_trait]
pub trait Client {
    async fn status(
        &self,
        request: crate::types::status::StatusRequest,
    ) -> Result<crate::types::status::StatusResponse, ClientError>;

    async fn list(&self) -> Result<Vec<crate::types::Metadata>, ClientError>;

    async fn upload(&self, request: crate::types::upload::UploadFile) -> Result<(), ClientError>;

    async fn download(
        &self,
        request: crate::types::download::DownloadRequest,
    ) -> Result<crate::types::download::DownloadedFile, ClientError>;
}

pub struct BiursClient {
    client: crate::proto::biurs_v1::back_it_up_client::BackItUpClient<tonic::transport::Channel>,
}

impl BiursClient {
    pub async fn new(url: String) -> Result<Self, ClientError> {
        Ok(Self {
            client: crate::proto::biurs_v1::back_it_up_client::BackItUpClient::connect(url).await?,
        })
    }
}

#[async_trait::async_trait]
impl Client for BiursClient {
    async fn status(
        &self,
        request: crate::types::status::StatusRequest,
    ) -> Result<crate::types::status::StatusResponse, ClientError> {
        let response = self
            .client
            .clone()
            .status(tonic::Request::new(request.into()))
            .await?;
        Ok(response.into_inner().try_into()?)
    }

    async fn list(&self) -> Result<Vec<crate::types::Metadata>, ClientError> {
        let response = self
            .client
            .clone()
            .list(tonic::Request::new(crate::proto::biurs_v1::ListRequest {}))
            .await?;
        Ok(response.into_inner().try_into()?)
    }

    async fn upload(&self, request: crate::types::upload::UploadFile) -> Result<(), ClientError> {
        use futures::StreamExt;

        let mut chunks = vec![crate::types::upload::UploadRequest::Meta(request.meta)];
        for chunk in request.data.chunks(2048) {
            chunks.push(crate::types::upload::UploadRequest::Data(chunk.to_vec()));
        }

        self.client
            .clone()
            .upload(futures::stream::iter(chunks).map(|chunk| chunk.into()))
            .await?;
        Ok(())
    }

    async fn download(
        &self,
        request: crate::types::download::DownloadRequest,
    ) -> Result<crate::types::download::DownloadedFile, ClientError> {
        let mut response = self
            .client
            .clone()
            .download(tonic::Request::new(request.into()))
            .await?
            .into_inner();

        let meta = response
            .message()
            .await?
            .ok_or(ClientError::MessageExpected)?;
        let meta: crate::types::download::DownloadResponse = meta.try_into()?;
        let meta = match meta {
            crate::types::download::DownloadResponse::Meta(meta) => meta,
            crate::types::download::DownloadResponse::Data(_) => {
                return Err(ClientError::UnexpectedMessageType)
            }
        };

        let mut data = Vec::<u8>::new();
        while let Some(message) = response.message().await? {
            let chunk: crate::types::download::DownloadResponse = message.try_into()?;
            match chunk {
                crate::types::download::DownloadResponse::Meta(_) => {
                    return Err(ClientError::UnexpectedMessageType)
                }
                crate::types::download::DownloadResponse::Data(chunk) => data.extend(chunk),
            }
        }

        Ok(crate::types::download::DownloadedFile { meta, data })
    }
}
