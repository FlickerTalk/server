# FlickerTalk server

The push router behind `api.flickertalk.com`. It is **not** a chat server: it wakes phones, helps
them connect to each other, and holds messages that could not be delivered — encrypted end to end,
so it cannot read them. [flickertalk.com](https://flickertalk.com)

## What it keeps

| Data | Why | For how long |
| --- | --- | --- |
| Device ID, public key, hash of the routing code | Authenticate a phone's signed requests | Until the user erases the phone |
| Push token, encrypted with a key kept outside the database | Wake a phone through FCM or APNs | Same, or until the provider says it expired |
| Undelivered messages, end-to-end encrypted, without sender | Deliver them later | Until picked up, at most 7 days |

No conversations, no contacts, no history, no access logs, no IP logs. There are no `/messages`,
`/conversations`, `/users` or `/profiles` endpoints, and there never will be.

## Running the tests

```sh
docker run -d --name ft-pg-test -e POSTGRES_PASSWORD=test -e POSTGRES_DB=ft_router_test \
  -p 127.0.0.1:55432:5432 postgres:17-alpine
cargo test --workspace
docker build -t ft-router .
```

The image is published to `ghcr.io/flickertalk/ft-router` by GitHub Actions: `canary` on every push
to `main`, and the version plus `latest` on every `vX.Y.Z` tag.

## Licence

[AGPL-3.0](LICENSE). The client is in [FlickerTalk/app](https://github.com/FlickerTalk/app).
Security issues: see [SECURITY.md](SECURITY.md).
