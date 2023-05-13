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
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("Unauthorized")]
    Unauthorized,
    #[error(transparent)]
    SystemTime(#[from] std::time::SystemTimeError),
    #[error(transparent)]
    Jwt(#[from] jsonwebtoken::errors::Error),
}

impl From<ServerError> for tonic::Status {
    fn from(value: ServerError) -> Self {
        match value {
            ServerError::Type(_) | ServerError::Json(_) => {
                tonic::Status::invalid_argument(value.to_string())
            }
            ServerError::Io(_)
            | ServerError::MessageExpected
            | ServerError::UnexpectedMessageType
            | ServerError::Send(_)
            | ServerError::Jwt(_)
            | ServerError::SystemTime(_) => tonic::Status::internal(value.to_string()),
            ServerError::Unauthorized => tonic::Status::unauthenticated(value.to_string()),
        }
    }
}

#[async_trait::async_trait]
pub trait Server {
    async fn auth(
        &self,
        mut rx_req: tokio::sync::mpsc::Receiver<crate::types::auth::AuthenticateRequest>,
        tx_res: tokio::sync::mpsc::Sender<crate::types::auth::AuthenticateResponse>,
    ) -> Result<(), ServerError>;

    async fn status(
        &self,
        request: crate::types::status::StatusRequest,
        auth_token: Option<String>,
    ) -> Result<crate::types::status::StatusResponse, ServerError>;

    async fn list(
        &self,
        auth_token: Option<String>,
    ) -> Result<Vec<crate::types::Metadata>, ServerError>;

    async fn download(
        &self,
        request: crate::types::download::DownloadRequest,
        auth_token: Option<String>,
    ) -> Result<tokio::sync::mpsc::Receiver<crate::types::download::DownloadResponse>, ServerError>;

    async fn upload(
        &self,
        mut rx: tokio::sync::mpsc::Receiver<crate::types::upload::UploadRequest>,
        auth_token: Option<String>,
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
    type AuthenticateStream = Pin<
        Box<
            dyn futures::Stream<Item = Result<proto::biurs_v1::AuthenticateResponse, tonic::Status>>
                + Send,
        >,
    >;

    type DownloadStream = Pin<
        Box<
            dyn futures::Stream<Item = Result<proto::biurs_v1::DownloadResponse, tonic::Status>>
                + Send,
        >,
    >;

    async fn authenticate(
        &self,
        request: tonic::Request<tonic::Streaming<proto::biurs_v1::AuthenticateRequest>>,
    ) -> Result<tonic::Response<Self::AuthenticateStream>, tonic::Status> {
        use tokio_stream::StreamExt;

        let mut request_stream = request.into_inner();
        let (tx_req, rx_req) =
            tokio::sync::mpsc::channel::<crate::types::auth::AuthenticateRequest>(64);
        let (tx_res, rx_res) =
            tokio::sync::mpsc::channel::<crate::types::auth::AuthenticateResponse>(64);

        tokio::spawn(async move {
            while let Some(result) = request_stream.next().await {
                let result = result?;
                let result: crate::types::auth::AuthenticateRequest = result.try_into()?;
                tx_req
                    .send(result)
                    .await
                    .map_err(|err| tonic::Status::internal(err.to_string()))?;
            }
            Ok::<(), tonic::Status>(())
        });

        let server_impl = self.server_impl.clone();
        tokio::spawn(async move {
            server_impl.auth(rx_req, tx_res).await?;
            Ok::<(), tonic::Status>(())
        });

        let stream = tokio_stream::wrappers::ReceiverStream::new(rx_res);
        Ok(tonic::Response::new(
            Box::pin(stream.map(|i| Ok(i.into()))) as Self::AuthenticateStream
        ))
    }

    async fn status(
        &self,
        request: tonic::Request<proto::biurs_v1::StatusRequest>,
    ) -> Result<tonic::Response<proto::biurs_v1::StatusResponse>, tonic::Status> {
        let auth_token = request
            .metadata()
            .get("authentication")
            .map(|value| value.to_str())
            .transpose()
            .map_err(|err| tonic::Status::internal(err.to_string()))?
            .map(|s| s.to_owned());

        let request = request.into_inner().try_into()?;
        let response = self.server_impl.status(request, auth_token).await?;
        Ok(tonic::Response::new(response.into()))
    }

    async fn list(
        &self,
        request: tonic::Request<proto::biurs_v1::ListRequest>,
    ) -> Result<tonic::Response<proto::biurs_v1::ListResponse>, tonic::Status> {
        let auth_token = request
            .metadata()
            .get("authentication")
            .map(|value| value.to_str())
            .transpose()
            .map_err(|err| tonic::Status::internal(err.to_string()))?
            .map(|s| s.to_owned());

        let response = self.server_impl.list(auth_token).await?;
        Ok(tonic::Response::new(response.into()))
    }

    async fn download(
        &self,
        request: tonic::Request<proto::biurs_v1::DownloadRequest>,
    ) -> Result<tonic::Response<Self::DownloadStream>, tonic::Status> {
        use tokio_stream::StreamExt;

        let auth_token = request
            .metadata()
            .get("authentication")
            .map(|value| value.to_str())
            .transpose()
            .map_err(|err| tonic::Status::internal(err.to_string()))?
            .map(|s| s.to_owned());

        let request = request.into_inner().into();
        let rx = self.server_impl.download(request, auth_token).await?;
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

        let auth_token = request
            .metadata()
            .get("authentication")
            .map(|value| value.to_str())
            .transpose()
            .map_err(|err| tonic::Status::internal(err.to_string()))?
            .map(|s| s.to_owned());

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

        self.server_impl.upload(rx, auth_token).await?;

        Ok(tonic::Response::new(proto::biurs_v1::UploadResponse {}))
    }
}
