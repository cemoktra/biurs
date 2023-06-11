use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    path::PathBuf,
    sync::Arc,
    time::SystemTime,
};

use biurs_core::client::Client;
use tokio::{io::AsyncWriteExt, task::JoinHandle};

#[derive(clap::Parser)]
struct Args {
    #[clap(subcommand)]
    pub cmd: SubCommand,
    #[clap(index = 1)]
    pub server: String,
}

#[derive(clap::Subcommand)]
enum SubCommand {
    Backup,
    Restore,
}

#[derive(serde::Deserialize)]
struct ClientConfig {
    private_key: String,
    folders: Vec<PathBuf>,
}

#[tracing::instrument(skip(client, auth_token))]
async fn backup_file(
    filepath: PathBuf,
    client: Arc<biurs_core::client::BiursClient>,
    auth_token: String,
) -> anyhow::Result<()> {
    tracing::info!("checking status");

    let data = tokio::fs::read(&filepath).await?;
    let meta = tokio::fs::metadata(&filepath).await?;
    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    let content_hash = hasher.finish().to_be_bytes().to_vec();

    let status = client
        .status(
            biurs_core::types::status::StatusRequest {
                file: filepath.clone(),
                content_hash: content_hash.clone(),
                modified_at: meta.modified()?,
            },
            &auth_token,
        )
        .await?;

    match status {
        biurs_core::types::status::StatusResponse::Missing => {
            tracing::warn!("file missing => uploading");

            client
                .upload(
                    biurs_core::types::upload::UploadFile {
                        meta: biurs_core::types::Metadata {
                            file: filepath,
                            content_hash,
                            modified_at: meta.modified()?,
                        },
                        data,
                    },
                    &auth_token,
                )
                .await?;
        }
        biurs_core::types::status::StatusResponse::Mismatch(mismatch) => {
            if mismatch.client_modified_at > mismatch.server_modified_at {
                tracing::warn!("remote file is not up 2 date => uploading",);

                client
                    .upload(
                        biurs_core::types::upload::UploadFile {
                            meta: biurs_core::types::Metadata {
                                file: filepath,
                                content_hash,
                                modified_at: meta.modified()?,
                            },
                            data,
                        },
                        &auth_token,
                    )
                    .await?;
            } else {
                tracing::warn!("client file is not up 2 date => handling not yet implemented",);
            }
        }
        biurs_core::types::status::StatusResponse::Match => {
            tracing::info!("file is backed up")
        }
    }
    Ok(())
}

#[tracing::instrument(skip(client, auth_token))]
async fn backup_folder(
    folder: PathBuf,
    client: Arc<biurs_core::client::BiursClient>,
    auth_token: String,
) -> anyhow::Result<()> {
    let mut folder_taks: Vec<JoinHandle<anyhow::Result<()>>> = Vec::new();

    for entry in walkdir::WalkDir::new(folder) {
        match entry {
            Ok(entry) => {
                if entry.file_type().is_file() {
                    let entry = entry.into_path();
                    let client = client.clone();
                    let auth_token = auth_token.clone();
                    folder_taks.push(tokio::task::spawn(backup_file(entry, client, auth_token)));
                }
            }
            Err(err) => tracing::error!("{err}"),
        }
    }

    for task in folder_taks {
        task.await??;
    }
    Ok(())
}

#[tracing::instrument(skip(client, auth_token))]
async fn restore_file(
    filepath: PathBuf,
    modified_at: SystemTime,
    client: Arc<biurs_core::client::BiursClient>,
    auth_token: String,
) -> anyhow::Result<()> {
    tracing::info!("restoring");
    if tokio::fs::try_exists(&filepath).await? {
        tracing::info!("file exists");
        return Ok(());
    }

    tracing::info!("downloading ...");
    let downloaded = client
        .download(
            biurs_core::types::download::DownloadRequest {
                file: filepath.clone(),
            },
            &auth_token,
        )
        .await?;

    {
        let mut file = tokio::fs::File::create(&filepath).await?;
        let _ = file.write(&downloaded.data).await?;
    }
    let modified_at = modified_at.into();
    filetime::set_file_mtime(filepath, modified_at)?;
    tracing::info!("downloaded");
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use clap::Parser;
    tracing_subscriber::fmt::init();

    let Args { cmd, server } = Args::parse();

    let base_dirs =
        directories::BaseDirs::new().ok_or(anyhow::anyhow!("Failed to get config dir"))?;
    let config_dir = base_dirs.config_dir();
    let config_data = tokio::fs::read(config_dir.join("biurs.json")).await?;
    let config: ClientConfig = serde_json::from_slice(&config_data)?;

    let key_data = tokio::fs::read(&config.private_key).await?;
    let encoding_key = jsonwebtoken::EncodingKey::from_ed_pem(&key_data)?;
    let client = Arc::new(biurs_core::client::BiursClient::new(server, encoding_key).await?);

    let auth_token = client.auth().await?;

    match cmd {
        SubCommand::Backup => {
            let mut folder_taks: Vec<JoinHandle<anyhow::Result<()>>> = Vec::new();
            for folder in config.folders.clone().into_iter() {
                let client = client.clone();
                let auth_token = auth_token.clone();
                folder_taks.push(tokio::task::spawn(backup_folder(
                    folder, client, auth_token,
                )));
            }

            for task in folder_taks {
                task.await??;
            }
        }
        SubCommand::Restore => {
            tracing::info!("listing remote files");

            let metas = client.list(&auth_token).await?;

            let mut restore_tasks: Vec<JoinHandle<anyhow::Result<()>>> = Vec::new();
            for meta in metas {
                let client = client.clone();
                let auth_token = auth_token.clone();
                restore_tasks.push(tokio::task::spawn(restore_file(
                    meta.file,
                    meta.modified_at,
                    client,
                    auth_token,
                )));
            }

            for task in restore_tasks {
                task.await??;
            }
        }
    }

    Ok(())
}
