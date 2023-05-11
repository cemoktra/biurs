# biurs

Personal backup toy project exploring gRPC streaming.

## Install
Server: `cargo install biurs-server`

Client: `cargo install biurs`

## Usage
Server: `biurs-server <backup-dir>`

Client: `biurs <url> backup/restore`

## Status
Works without authentication, so only in private network where the port is not exposed.

## Plans
- [ ] authentication 
- [ ] concurrent execution
