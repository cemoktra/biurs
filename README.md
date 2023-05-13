# biurs

**b**ack **i**t **u**p - written in **rs**

Personal backup toy project exploring gRPC streaming.

## Install
Server: `cargo install biurs-server`

Client: `cargo install biurs`

## Config

### Server
A json file containing an array of paths to PEM encoded Ed25519 public keys of clients.

```
[
  "/path/to/user_1.public",
  "/path/to/user_2.public"
]
```

### Client
A json file with the following structure:

```
{
  "private_key": "/path/to/pem/encoded/private/key/of/user",
  "folder": [
    "/path/to/folders_to_back_up"
  ]
}
```

## Usage
Server: `biurs-server <backup-dir>`

Client: `biurs <url> backup/restore`

## Status
- [x] authentication 
- [ ] concurrent execution
