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
| Undelivered messages, end-to-end encrypted, without sender, each with the number (0–7) of the routing code it came through | Deliver them later; hold back those for a session the user has left; give each routing code its own quota | Until picked up, at most 7 days |
| Connection offers and answers for a phone that is not connected, end-to-end encrypted | Hand them over as soon as it connects | In memory only, never on disk: until it connects, at most 55 seconds |
| How many suggestions each device has sent in the last 24 hours | Limit suggestions | In memory only, never on disk or in a log |

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
mail expires after 7 days like any other. A signal held for a phone remembers its code too, and if
that code has become silent by the time the phone connects, it is dropped instead of handed over.
The phone sets the bits of its unused codes at random, so the bits do not tell how many sessions it
has.

Each routing code has its own mailbox quota: up to 1000 messages waiting through the main list and
200 through each other code, so a session whose mail is withheld cannot fill the main list's. A full
code answers `507` for that code only, exactly as a full mailbox does, silent or not.

## Suggestions

`POST /v1/feedback`, signed like every other request, takes `{"text", "app", "platform"}`: a
suggestion typed in the app (1 to 2000 characters), the app's version and its platform. The router
forwards the text by email to the project's mailbox and does not store it: nothing goes to the
database or to a log. The mail carries the text, the version and the platform in its subject, and
no device ID, nor the phone's IP address or clock. While it handles the request the router sees
which device sent it, as with any signed request, to check the signature and the limits: three
suggestions per device and 200 in all every 24 hours, counting only those delivered. It answers
`204` once the mail server has taken the mail, `400` for a malformed suggestion, `413` for a body
over 32 KiB, `429` over a limit and `503` when mail is not set up or the mail server did not take
it. The router always talks to
the mail server over STARTTLS.

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
