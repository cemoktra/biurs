use jsonwebtoken::EncodingKey;

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
    #[error("Channel send error: {0}")]
    Send(String),
    #[error(transparent)]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error(transparent)]
    InvalidMetadata(#[from] tonic::metadata::errors::InvalidMetadataValue),
    #[error("Unauthorized")]
    Unauthorized,
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[async_trait::async_trait]
pub trait Client {
    async fn auth(&self) -> Result<String, ClientError>;

    async fn status(
        &self,
        request: crate::types::status::StatusRequest,
        auth_token: &str,
    ) -> Result<crate::types::status::StatusResponse, ClientError>;

    async fn list(&self, auth_token: &str) -> Result<Vec<crate::types::Metadata>, ClientError>;

    async fn upload(
        &self,
        request: crate::types::upload::UploadFile,
        auth_token: &str,
    ) -> Result<(), ClientError>;

    async fn download(
        &self,
        request: crate::types::download::DownloadRequest,
        auth_token: &str,
    ) -> Result<crate::types::download::DownloadedFile, ClientError>;
}

pub struct BiursClient {
    client: crate::proto::biurs_v1::back_it_up_client::BackItUpClient<tonic::transport::Channel>,
    encoding_key: jsonwebtoken::EncodingKey,
}

impl BiursClient {
    pub async fn new(url: String, encoding_key: EncodingKey) -> Result<Self, ClientError> {
        Ok(Self {
            client: crate::proto::biurs_v1::back_it_up_client::BackItUpClient::connect(url).await?,
            encoding_key,
        })
    }
}

#[async_trait::async_trait]
impl Client for BiursClient {
    async fn auth(&self) -> Result<String, ClientError> {
        let (tx_req, rx_req) =
            tokio::sync::mpsc::channel::<crate::proto::biurs_v1::AuthenticateRequest>(64);
        let stream = tokio_stream::wrappers::ReceiverStream::new(rx_req);
        let mut response = self
            .client
            .clone()
            .authenticate(tonic::Request::new(stream))
            .await?
            .into_inner();

        tracing::info!("sending challenge request");
        let create_challenge = crate::types::auth::AuthenticateRequest::CreateChallenge;
        tx_req
            .send(create_challenge.into())
            .await
            .map_err(|err| ClientError::Send(err.to_string()))?;

        tracing::info!("reading challenge");
        let message: crate::types::auth::AuthenticateResponse = response
            .message()
            .await?
            .ok_or(ClientError::MessageExpected)?
            .try_into()?;
        let signature = match message {
            crate::types::auth::AuthenticateResponse::Challenge(challenge) => {
                let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
                let claims =
                    serde_json::from_str::<crate::types::auth::ChallengeClaims>(&challenge)?;
                jsonwebtoken::encode(&header, &claims, &self.encoding_key)?
            }
            crate::types::auth::AuthenticateResponse::Token(_) => {
                return Err(ClientError::UnexpectedMessageType)
            }
            crate::types::auth::AuthenticateResponse::Unauthorized => {
                return Err(ClientError::Unauthorized)
            }
        };

        tracing::info!("sending signature");
        tx_req
            .send(crate::types::auth::AuthenticateRequest::VerifyChallenge(signature).into())
            .await
            .map_err(|err| ClientError::Send(err.to_string()))?;

        tracing::info!("reading token");
        let message: crate::types::auth::AuthenticateResponse = response
            .message()
            .await?
            .ok_or(ClientError::MessageExpected)?
            .try_into()?;
        let token = match message {
            crate::types::auth::AuthenticateResponse::Challenge(_) => {
                return Err(ClientError::UnexpectedMessageType)
            }
            crate::types::auth::AuthenticateResponse::Token(token) => token,
            crate::types::auth::AuthenticateResponse::Unauthorized => {
                return Err(ClientError::Unauthorized)
            }
        };

        Ok(token)
    }

    async fn status(
        &self,
        request: crate::types::status::StatusRequest,
        auth_token: &str,
    ) -> Result<crate::types::status::StatusResponse, ClientError> {
        let mut request = tonic::Request::new(request.into());
        request
            .metadata_mut()
            .append("authentication", auth_token.try_into()?);
        let response = self.client.clone().status(request).await?;
        Ok(response.into_inner().try_into()?)
    }

    async fn list(&self, auth_token: &str) -> Result<Vec<crate::types::Metadata>, ClientError> {
        let mut request = tonic::Request::new(crate::proto::biurs_v1::ListRequest {});
        request
            .metadata_mut()
            .append("authentication", auth_token.try_into()?);

        let response = self.client.clone().list(request).await?;
        Ok(response.into_inner().try_into()?)
    }

    async fn upload(
        &self,
        request: crate::types::upload::UploadFile,
        auth_token: &str,
    ) -> Result<(), ClientError> {
        use futures::StreamExt;

        let mut chunks = vec![crate::types::upload::UploadRequest::Meta(request.meta)];
        for chunk in request.data.chunks(2048) {
            chunks.push(crate::types::upload::UploadRequest::Data(chunk.to_vec()));
        }

        let streaming_req = StreamingRequestWithAuth {
            auth_token: auth_token.try_into()?,
            request: futures::stream::iter(chunks).map(|chunk| chunk.into()),
        };

        self.client.clone().upload(streaming_req).await?;
        Ok(())
    }

    async fn download(
        &self,
        request: crate::types::download::DownloadRequest,
        auth_token: &str,
    ) -> Result<crate::types::download::DownloadedFile, ClientError> {
        let mut request = tonic::Request::new(request.into());
        request
            .metadata_mut()
            .append("authentication", auth_token.try_into()?);

        let mut response = self.client.clone().download(request).await?.into_inner();

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

struct StreamingRequestWithAuth<T> {
    auth_token: tonic::metadata::MetadataValue<tonic::metadata::Ascii>,
    request: T,
}

impl<T: tonic::IntoStreamingRequest<Message = crate::proto::biurs_v1::UploadRequest>>
    tonic::IntoStreamingRequest for StreamingRequestWithAuth<T>
{
    type Stream = T::Stream;
    type Message = T::Message;

    fn into_streaming_request(self) -> tonic::Request<Self::Stream> {
        let mut request = self.request.into_streaming_request();
        request
            .metadata_mut()
            .append("authentication", self.auth_token);
        request
    }
}
