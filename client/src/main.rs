use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    path::PathBuf,
};

use biurs_core::client::Client;
use tokio::io::AsyncWriteExt;

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
    let client = biurs_core::client::BiursClient::new(server, encoding_key).await?;

    let auth_token = client.auth().await?;

    match cmd {
        SubCommand::Backup => {
            for folder in &config.folders {
                for entry in walkdir::WalkDir::new(folder) {
                    match entry {
                        Ok(entry) => {
                            if entry.file_type().is_file() {
                                let entry = entry.into_path();
                                tracing::info!("checking status of '{}'", entry.display());

                                let data = tokio::fs::read(&entry).await?;
                                let meta = tokio::fs::metadata(&entry).await?;
                                let mut hasher = DefaultHasher::new();
                                data.hash(&mut hasher);
                                let content_hash = hasher.finish().to_be_bytes().to_vec();

                                let status = client
                                    .status(
                                        biurs_core::types::status::StatusRequest {
                                            file: entry.clone(),
                                            content_hash: content_hash.clone(),
                                            modified_at: meta.modified()?,
                                        },
                                        &auth_token,
                                    )
                                    .await?;

                                match status {
                                    biurs_core::types::status::StatusResponse::Missing => {
                                        tracing::warn!(
                                            "file '{}' is missing, uploading ...",
                                            entry.display()
                                        );

                                        client
                                            .upload(
                                                biurs_core::types::upload::UploadFile {
                                                    meta: biurs_core::types::Metadata {
                                                        file: entry,
                                                        content_hash,
                                                        modified_at: meta.modified()?,
                                                    },
                                                    data,
                                                },
                                                &auth_token,
                                            )
                                            .await?;
                                    }
                                    biurs_core::types::status::StatusResponse::Mismatch(
                                        mismatch,
                                    ) => {
                                        if mismatch.client_modified_at > mismatch.server_modified_at
                                        {
                                            tracing::warn!(
                                                "remote file '{}' is not up 2 date, uploading ...",
                                                entry.display()
                                            );

                                            client
                                                .upload(
                                                    biurs_core::types::upload::UploadFile {
                                                        meta: biurs_core::types::Metadata {
                                                            file: entry,
                                                            content_hash,
                                                            modified_at: meta.modified()?,
                                                        },
                                                        data,
                                                    },
                                                    &auth_token,
                                                )
                                                .await?;
                                        } else {
                                            tracing::warn!(
                                                "client file '{}' is not up 2 date, handling not yet implemented ...",
                                                entry.display()
                                            );
                                        }
                                    }
                                    biurs_core::types::status::StatusResponse::Match => {
                                        tracing::info!("file '{}' is backed up", entry.display())
                                    }
                                }
                            }
                        }
                        Err(err) => tracing::error!("{err}"),
                    }
                }
            }
        }
        SubCommand::Restore => {
            tracing::info!("listing remote files");

            let metas = client.list(&auth_token).await?;
            for meta in metas {
                tracing::info!("trying to restore '{}' ...", meta.file.display());
                if tokio::fs::try_exists(&meta.file).await? {
                    tracing::info!("'{}' exists", meta.file.display());
                    continue;
                }

                tracing::info!("downloading '{}' ...", meta.file.display());

                let downloaded = client
                    .download(
                        biurs_core::types::download::DownloadRequest {
                            file: meta.file.clone(),
                        },
                        &auth_token,
                    )
                    .await?;

                {
                    let mut file = tokio::fs::File::create(&meta.file).await?;
                    let _ = file.write(&downloaded.data).await?;
                }
                let modified_at = meta.modified_at.into();
                filetime::set_file_mtime(meta.file, modified_at)?;
            }
        }
    }

    Ok(())
}
