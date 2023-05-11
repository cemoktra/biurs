use std::{pin::Pin, sync::Arc};

use crate::proto;

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error(transparent)]
    Type(#[from] crate::types::TypeError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("Expected message")]
    MessageExpected,
    #[error("Unexpected message type")]
    UnexpectedMessageType,
    #[error("Channel send error: {0}")]
    Send(String),
}

impl From<ServerError> for tonic::Status {
    fn from(value: ServerError) -> Self {
        match value {
            ServerError::Type(_) => tonic::Status::invalid_argument(value.to_string()),
            ServerError::Io(_)
            | ServerError::MessageExpected
            | ServerError::UnexpectedMessageType
            | ServerError::Send(_) => tonic::Status::internal(value.to_string()),
        }
    }
}

#[async_trait::async_trait]
pub trait Server {
    async fn status(
        &self,
        request: crate::types::status::StatusRequest,
    ) -> Result<crate::types::status::StatusResponse, ServerError>;

    async fn list(&self) -> Result<Vec<crate::types::Metadata>, ServerError>;

    async fn download(
        &self,
        request: crate::types::download::DownloadRequest,
    ) -> Result<tokio::sync::mpsc::Receiver<crate::types::download::DownloadResponse>, ServerError>;

    async fn upload(
        &self,
        mut rx: tokio::sync::mpsc::Receiver<crate::types::upload::UploadRequest>,
    ) -> Result<(), ServerError>;
}

pub struct BiursServer {
    server_impl: Arc<dyn Server + Send + Sync + 'static>,
}

impl BiursServer {
    pub fn new(server: impl Server + Send + Sync + 'static) -> Self {
        Self {
            server_impl: Arc::new(server),
        }
    }
}

#[async_trait::async_trait]
impl proto::biurs_v1::back_it_up_server::BackItUp for BiursServer {
    type DownloadStream = Pin<
        Box<
            dyn futures::Stream<Item = Result<proto::biurs_v1::DownloadResponse, tonic::Status>>
                + Send,
        >,
    >;

    async fn status(
        &self,
        request: tonic::Request<proto::biurs_v1::StatusRequest>,
    ) -> Result<tonic::Response<proto::biurs_v1::StatusResponse>, tonic::Status> {
        let request = request.into_inner().try_into()?;
        let response = self.server_impl.status(request).await?;
        Ok(tonic::Response::new(response.into()))
    }

    async fn list(
        &self,
        _request: tonic::Request<proto::biurs_v1::ListRequest>,
    ) -> Result<tonic::Response<proto::biurs_v1::ListResponse>, tonic::Status> {
        let response = self.server_impl.list().await?;
        Ok(tonic::Response::new(response.into()))
    }

    async fn download(
        &self,
        request: tonic::Request<proto::biurs_v1::DownloadRequest>,
    ) -> Result<tonic::Response<Self::DownloadStream>, tonic::Status> {
        use tokio_stream::StreamExt;

        let request = request.into_inner().into();
        let rx = self.server_impl.download(request).await?;
        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);

        Ok(tonic::Response::new(
            Box::pin(stream.map(|i| Ok(i.into()))) as Self::DownloadStream
        ))
    }

    async fn upload(
        &self,
        request: tonic::Request<tonic::Streaming<proto::biurs_v1::UploadRequest>>,
    ) -> Result<tonic::Response<proto::biurs_v1::UploadResponse>, tonic::Status> {
        use tokio_stream::StreamExt;

        let mut stream = request.into_inner();
        let (tx, rx) = tokio::sync::mpsc::channel::<crate::types::upload::UploadRequest>(64);

        tokio::spawn(async move {
            while let Some(result) = stream.next().await {
                let result = result?;
                let result: crate::types::upload::UploadRequest = result.try_into()?;
                tx.send(result)
                    .await
                    .map_err(|err| tonic::Status::internal(err.to_string()))?;
            }
            Ok::<(), tonic::Status>(())
        });

        self.server_impl.upload(rx).await?;

        Ok(tonic::Response::new(proto::biurs_v1::UploadResponse {}))
    }
}
