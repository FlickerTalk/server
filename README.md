# FlickerTalk server

The push router behind `api.flickertalk.com`. It is **not** a chat server: it wakes phones, helps
them connect to each other, and holds messages that could not be delivered — encrypted end to end,
so it cannot read them. [flickertalk.com](https://flickertalk.com)

## What it keeps

| Data | Why | For how long |
| --- | --- | --- |
| Device ID, public key, hash of the routing code | Authenticate a phone's signed requests | Until the user erases the phone |
| Push token, encrypted with a key kept outside the database | Wake a phone through FCM or APNs | Same, or until the provider says it expired |
| Which of the phone's eight routing codes are silent: eight bits, nothing else | Keep a session the user has left unreachable | Replaced at every registration; until the user erases the phone |
| Undelivered messages, end-to-end encrypted, without sender, each with the number (0–7) of the routing code it came through | Deliver them later; hold back those for a session the user has left | Until picked up, at most 7 days |
| Connection offers and answers for a phone that is not connected, end-to-end encrypted | Hand them over as soon as it connects | In memory only, never on disk: until it connects, at most 55 seconds |

A signal for a phone that is not connected is answered `404` with `ft-retained: 1`: the router
wakes the phone and holds the signal in memory (eight per phone and 32 MiB in all, the oldest
dropped first) to hand it over, in order and once, when the phone connects. Because it lives in
memory, the router runs as a single replica.

A caller marks a call's signal with `ft-call: 1`, and the phone is rung instead of woken. Wakes and
rings are paced apart, per phone and routing code, so a message never holds back a call: a phone is
woken at most once every 10 seconds, and after a ring the next one waits until the phone has
connected and 10 seconds have passed, or until the ring has run out after 45 seconds: a call sent
again before the phone has connected does not ring it twice. The paces live in memory only, and the
sender gets the same answer whether a push went out or not.

A phone registers eight routing codes, most of them unused, and may say which are silent
(`silent_slots`, bit *i* for code *i*; the first, the main list, is never silent). A silent code
belongs to a session the user has left, and the router keeps it unreachable whether the app is
open or not: nothing is pushed for it; a signal or a call through it is neither delivered nor held,
and its sender gets the answer of a phone that is not connected (`404` with `ft-retained: 1`); mail
through it is kept with the usual answer, but the phone is not told of it and does not collect it
until a registration clears that bit, when a connected phone gets the usual mail notice. Withheld
mail expires after 7 days like any other. The phone sets the bits of its unused codes at random, so
the bits do not tell how many sessions it has.

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

The FlickerTalk name and logo are not licensed under the AGPL (section 7(e)): forks are welcome,
but must use their own name and icon. The public router at `api.flickertalk.com` serves the
official FlickerTalk apps only; a fork should run its own router from this repository.
