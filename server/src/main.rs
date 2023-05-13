use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
};

use rand::{distributions::Alphanumeric, Rng};
use ring::signature::KeyPair;

#[derive(clap::Parser)]
struct Args {
    #[clap(long, default_value = "50000")]
    pub port: u16,

    #[clap(long, default_value = "false")]
    pub ip6: bool,

    #[clap(index = 1)]
    pub storage_folder: PathBuf,
}

struct Server {
    pub storage_folder: PathBuf,
    pub auth_encoding: jsonwebtoken::EncodingKey,
    pub auth_decoding: jsonwebtoken::DecodingKey,
    pub user_decoding: Vec<jsonwebtoken::DecodingKey>,
}

impl Server {
    fn build_path(&self, file: &Path) -> PathBuf {
        if file.has_root() {
            let file = file.display().to_string();
            let stripped = file.strip_prefix('/').expect("is root");
            self.storage_folder.join(stripped)
        } else {
            self.storage_folder.join(file)
        }
    }

    fn check_auth(&self, token: &str) -> Result<(), biurs_core::server::ServerError> {
        tracing::info!("checking auth token ...");
        let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
        let _auth = jsonwebtoken::decode::<biurs_core::types::auth::AuthClaims>(
            token,
            &self.auth_decoding,
            &validation,
        )?;
        tracing::info!("authenticated");
        Ok(())
    }
}

#[async_trait::async_trait]
impl biurs_core::server::Server for Server {
    async fn auth(
        &self,
        mut rx_req: tokio::sync::mpsc::Receiver<biurs_core::types::auth::AuthenticateRequest>,
        tx_res: tokio::sync::mpsc::Sender<biurs_core::types::auth::AuthenticateResponse>,
    ) -> Result<(), biurs_core::server::ServerError> {
        let challenge = biurs_core::types::auth::ChallengeClaims {
            challenge: rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(7)
                .map(char::from)
                .collect(),
            exp: (std::time::SystemTime::now() + std::time::Duration::from_secs(600))
                .duration_since(std::time::SystemTime::UNIX_EPOCH)?
                .as_secs(),
        };

        tracing::info!("receiving create challenge");
        match rx_req
            .recv()
            .await
            .ok_or(biurs_core::server::ServerError::MessageExpected)?
        {
            biurs_core::types::auth::AuthenticateRequest::CreateChallenge => {
                let challenge = serde_json::to_string(&challenge)?;
                tracing::info!("sending challenge");
                tx_res
                    .send(biurs_core::types::auth::AuthenticateResponse::Challenge(
                        challenge,
                    ))
                    .await
                    .map_err(|err| biurs_core::server::ServerError::Send(err.to_string()))?;
            }
            biurs_core::types::auth::AuthenticateRequest::VerifyChallenge(_) => {
                return Err(biurs_core::server::ServerError::UnexpectedMessageType)
            }
        }

        tracing::info!("receiving signature");
        match rx_req
            .recv()
            .await
            .ok_or(biurs_core::server::ServerError::MessageExpected)?
        {
            biurs_core::types::auth::AuthenticateRequest::CreateChallenge => {
                return Err(biurs_core::server::ServerError::UnexpectedMessageType)
            }
            biurs_core::types::auth::AuthenticateRequest::VerifyChallenge(verify) => {
                for key in &self.user_decoding {
                    match biurs_core::types::auth::ChallengeClaims::decode(&verify, key) {
                        Ok(decoded) => {
                            if decoded.challenge == challenge.challenge {
                                let claims = biurs_core::types::auth::AuthClaims {
                                    exp: (std::time::SystemTime::now()
                                        + std::time::Duration::from_secs(600))
                                    .duration_since(std::time::SystemTime::UNIX_EPOCH)?
                                    .as_secs(),
                                };
                                let header =
                                    jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
                                tracing::info!("sending token");
                                tx_res
                                    .send(biurs_core::types::auth::AuthenticateResponse::Token(
                                        jsonwebtoken::encode(
                                            &header,
                                            &claims,
                                            &self.auth_encoding,
                                        )?,
                                    ))
                                    .await
                                    .map_err(|err| {
                                        biurs_core::server::ServerError::Send(err.to_string())
                                    })?;
                                return Ok(());
                            }
                        }
                        Err(err) => tracing::info!("could not decode: {err}"),
                    }
                }

                tracing::info!("no key matched signature");
                tx_res
                    .send(biurs_core::types::auth::AuthenticateResponse::Unauthorized)
                    .await
                    .map_err(|err| biurs_core::server::ServerError::Send(err.to_string()))?;
                return Err(biurs_core::server::ServerError::Unauthorized);
            }
        }
    }

    async fn status(
        &self,
        request: biurs_core::types::status::StatusRequest,
        auth_token: Option<String>,
    ) -> Result<biurs_core::types::status::StatusResponse, biurs_core::server::ServerError> {
        let filepath = self.build_path(&request.file);
        let hash_file = filepath.join("hash");
        tracing::info!("requesting status of '{}'", filepath.display());

        self.check_auth(
            auth_token
                .as_ref()
                .ok_or(biurs_core::server::ServerError::Unauthorized)?,
        )?;

        match tokio::fs::read(&hash_file).await {
            Ok(hash) => {
                if hash == request.content_hash {
                    Ok(biurs_core::types::status::StatusResponse::Match)
                } else {
                    let file_meta = tokio::fs::metadata(&hash_file).await?;
                    Ok(biurs_core::types::status::StatusResponse::Mismatch(
                        biurs_core::types::status::Mismatch {
                            server_modified_at: file_meta.modified()?,
                            client_modified_at: request.modified_at,
                        },
                    ))
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                Ok(biurs_core::types::status::StatusResponse::Missing)
            }
            Err(err) => Err(err.into()),
        }
    }

    async fn list(
        &self,
        auth_token: Option<String>,
    ) -> Result<Vec<biurs_core::types::Metadata>, biurs_core::server::ServerError> {
        self.check_auth(
            auth_token
                .as_ref()
                .ok_or(biurs_core::server::ServerError::Unauthorized)?,
        )?;
        let mut metas = vec![];
        for entry in walkdir::WalkDir::new(&self.storage_folder) {
            match entry {
                Ok(entry) => {
                    if entry.file_type().is_file() {
                        let entry = entry.into_path();
                        tracing::info!("listing: {}", entry.display());

                        if let Some("hash") = entry.file_name().and_then(std::ffi::OsStr::to_str) {
                            let content_hash = tokio::fs::read(&entry).await?;
                            let file_meta = tokio::fs::metadata(&entry).await?;
                            let parent = entry
                                .parent()
                                .expect("always has a parent")
                                .display()
                                .to_string();
                            let parent = parent
                                .strip_prefix(&self.storage_folder.display().to_string())
                                .expect("msg");

                            metas.push(biurs_core::types::Metadata {
                                file: parent.into(),
                                content_hash,
                                modified_at: file_meta.modified()?,
                            })
                        }
                    }
                }
                Err(err) => tracing::error!("{err}"),
            }
        }
        Ok(metas)
    }

    async fn download(
        &self,
        request: biurs_core::types::download::DownloadRequest,
        auth_token: Option<String>,
    ) -> Result<
        tokio::sync::mpsc::Receiver<biurs_core::types::download::DownloadResponse>,
        biurs_core::server::ServerError,
    > {
        self.check_auth(
            auth_token
                .as_ref()
                .ok_or(biurs_core::server::ServerError::Unauthorized)?,
        )?;
        let filepath = self.build_path(&request.file);
        let data_file = filepath.join("data");
        let hash_file = filepath.join("hash");
        let data = tokio::fs::read(&data_file).await?;
        let content_hash = tokio::fs::read(&hash_file).await?;
        let file_meta = tokio::fs::metadata(&hash_file).await?;

        let (tx, rx) =
            tokio::sync::mpsc::channel::<biurs_core::types::download::DownloadResponse>(64);
        tokio::spawn(async move {
            tx.send(biurs_core::types::download::DownloadResponse::Meta(
                biurs_core::types::Metadata {
                    file: request.file,
                    content_hash,
                    modified_at: file_meta.modified()?,
                },
            ))
            .await
            .map_err(|err| biurs_core::server::ServerError::Send(err.to_string()))?;

            for chunk in data.chunks(2048) {
                tx.send(biurs_core::types::download::DownloadResponse::Data(
                    chunk.to_vec(),
                ))
                .await
                .map_err(|err| biurs_core::server::ServerError::Send(err.to_string()))?;
            }

            Ok::<(), biurs_core::server::ServerError>(())
        });

        Ok(rx)
    }

    async fn upload(
        &self,
        mut rx: tokio::sync::mpsc::Receiver<biurs_core::types::upload::UploadRequest>,
        auth_token: Option<String>,
    ) -> Result<(), biurs_core::server::ServerError> {
        self.check_auth(
            auth_token
                .as_ref()
                .ok_or(biurs_core::server::ServerError::Unauthorized)?,
        )?;
        use tokio::io::AsyncWriteExt;

        let message = rx
            .recv()
            .await
            .ok_or(biurs_core::server::ServerError::MessageExpected)?;
        let meta = match message {
            biurs_core::types::upload::UploadRequest::Meta(meta) => meta,
            biurs_core::types::upload::UploadRequest::Data(_) => {
                return Err(biurs_core::server::ServerError::UnexpectedMessageType)
            }
        };
        let modified_at = meta.modified_at.into();
        let filepath = self.build_path(&meta.file);
        tokio::fs::create_dir_all(&filepath).await?;
        let data_file = filepath.join("data");
        let hash_file = filepath.join("hash");
        tracing::info!("uploading '{}'", filepath.display());

        let mut file = tokio::fs::File::create(&data_file).await?;

        while let Some(message) = rx.recv().await {
            match message {
                biurs_core::types::upload::UploadRequest::Meta(_) => {
                    return Err(biurs_core::server::ServerError::UnexpectedMessageType);
                }
                biurs_core::types::upload::UploadRequest::Data(data) => file.write(&data).await?,
            };
        }

        tokio::fs::write(&hash_file, &meta.content_hash).await?;
        filetime::set_file_mtime(data_file, modified_at)?;
        filetime::set_file_mtime(hash_file, modified_at)?;

        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use clap::Parser;
    tracing_subscriber::fmt::init();

    let Args {
        storage_folder,
        port,
        ip6,
    } = Args::parse();

    std::fs::create_dir_all(&storage_folder)?;

    let doc = ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())?;
    let auth_encoding = jsonwebtoken::EncodingKey::from_ed_der(doc.as_ref());
    let pair = ring::signature::Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap();
    let auth_decoding = jsonwebtoken::DecodingKey::from_ed_der(pair.public_key().as_ref());

    let mut user_decoding = vec![];
    let base_dirs =
        directories::BaseDirs::new().ok_or(anyhow::anyhow!("Failed to get config dir"))?;
    let config_dir = base_dirs.config_dir();
    let config_data = tokio::fs::read(config_dir.join("biurs_server.json")).await?;
    let config: Vec<PathBuf> = serde_json::from_slice(&config_data)?;

    for key_file in config {
        let content = tokio::fs::read(&key_file).await?;
        match jsonwebtoken::DecodingKey::from_ed_pem(&content) {
            Ok(decoding_key) => user_decoding.push(decoding_key),
            Err(err) => tracing::error!("{err}"),
        }
    }

    let server = Server {
        storage_folder,
        auth_decoding,
        auth_encoding,
        user_decoding,
    };
    let grpc_server = biurs_core::server::BiursServer::new(server);

    let addr = if ip6 {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
    };
    tonic::transport::Server::builder()
        .add_service(
            biurs_core::proto::biurs_v1::back_it_up_server::BackItUpServer::new(grpc_server),
        )
        .serve(addr)
        .await?;

    Ok(())
}
