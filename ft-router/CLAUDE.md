# server/ft-router

Push router de `api.flickertalk.com` (`§8–19`, `§74`, `§91`): resuelve `device_id → push target`,
despierta dispositivos vía FCM (Android) y APNs directo (iOS, `§11`) y mantiene el **buzón
cifrado efímero** para los mensajes que no pudieron entregarse por P2P (`§19`).

Stack: Rust + Axum + Tokio + PostgreSQL + serde + `tracing` mínimo. Se despliega como imagen
Docker con varias réplicas **sin estado** detrás de un balanceador: todo el estado va en
PostgreSQL (`§74–75`; los detalles de infraestructura están en el repo privado).

## Datos

Registro de dispositivos (`§8`):

```text
devices(device_id BLOB PRIMARY KEY, push_provider INTEGER, push_target BLOB)
-- opcionales: push_version, updated_at
```

- `push_target` va **cifrado** con una clave maestra que vive fuera de la BD
  (`/etc/flickertalk/secrets/push-key` o secret manager) (`§9`).
- El registro es reconstruible (el cliente se vuelve a registrar): sin backups históricos
  (`§73`). Se borran registros cuando FCM/APNs indican que el token ya no es válido (`§8`).

Buzón (`§19`): solo blobs cifrados E2EE por destinatario. Se borran al recibir el ACK o al
caducar (TTL provisional: 7 días). **Nunca** historial, conversaciones ni backups.

El buzón es **opcional** por usuario y está activado por defecto (`§19`). El router **no guarda
ninguna preferencia**: cada petición lleva el indicador `store` y se fía de él; con
`store = false` no conserva nada. Un dispositivo con el buzón desactivado puede pedir (firmado) el
borrado de sus blobs pendientes.

Ficheros y llamadas nunca pasan por el buzón (`§62`, `§66`).

## API (`§10`, nombres del buzón provisionales)

`POST /v1/device/register`, `PUT /v1/device/push`, `DELETE /v1/device`,
`POST /v1/wake/{device_id}`, `POST /v1/mailbox/{device_id}`, `GET /v1/mailbox`,
`DELETE /v1/mailbox/{blob_id}`, `GET /v1/turn-credentials`; más adelante, quizá
`POST /v1/signal/{device_id}`.

## Reglas

- **Nunca interpreta el contenido**: signaling y blobs del buzón son bytes opacos (`§14`). El blob
  temporal de signaling, si hace falta, vive solo en memoria, con TTL de 30–60 s (`§15`).
- Peticiones **firmadas**; `wake` y depositar en el buzón exigen una `route_capability` válida;
  rate limits y cuotas por destinatario (`§7`, `§34`, `§91`).
- **Logs** (`§71`): sin access logs, sin cuerpos, sin `device_id`, push tokens ni IPs. Métricas
  solo agregadas (`requests_total`, `wake_success_total`, `wake_failure_total`, `fcm_latency`,
  `apns_latency`, `http_errors`) y sin etiquetas identificativas.
- **Credenciales TURN** (`§17`): temporales (minutos), con un usuario aleatorio por sesión, nunca
  el `device_id`, y contraseña HMAC con el secreto compartido de coturn.
- Los **reportes** de abuso no van aquí: infraestructura separada (`§36`).

## Pendiente de diseño

- Cómo obtiene el router la clave pública para verificar firmas (el plan solo fija
  `device_id = BLAKE3(public_identity_key)`).
- Buzón (`§19`): va en PostgreSQL (infraestructura en el repo privado), TTL definitivo,
  sealed sender (que el servidor no sepa quién envía), tamaño máximo y cuotas.

## Estado: API v1 (2026-09-22, `§106` M2)

- **Peticiones firmadas** (`auth.rs`, `§7`): cabeceras `ft-device`, `ft-time`, `ft-nonce` y
  `ft-signature` (Ed25519, base64 sin relleno) sobre
  `FT1\n{METODO}\n{RUTA}\n{hora ms}\n{nonce}\n{hex BLAKE3 del cuerpo}`. Ventana de ±5 min y cada
  nonce una sola vez por dispositivo. El cliente (`ft-push`) construye el mismo texto: los dos lados
  lo fijan con tests.
- **PostgreSQL** (`db.rs`): `devices` (clave pública y hash de la route capability) y `mailbox`
  **UNLOGGED** (sin remitente ni fecha de creación; caduca a los 7 días, máx. 64 KiB por blob y 1000
  por dispositivo). Un test comprueba en `pg_class` que el buzón es `UNLOGGED`.
- **Rutas** (`v1.rs`): `POST /v1/device/register`, `DELETE /v1/device`, `GET /v1/connect`
  (WebSocket firmado: bienvenida con STUN y usuario TURN, señales y aviso de correo),
  `POST /v1/signal/{to}` (capability del destinatario; 404 si no está conectado),
  `POST /v1/mailbox/{to}` (capability, sin identidad del remitente), `GET /v1/mailbox`,
  `DELETE /v1/mailbox/{id}` y `GET /v1/turn-credentials`.
- Las conexiones viven en memoria: la señalización exige **una réplica** hasta repartirla con
  PostgreSQL.
- Configuración: `FT_DATABASE_URL` o `FT_DATABASE_URL_FILE` (secret de Swarm), `FT_STUN_URLS`,
  `FT_TURN_URLS`, `FT_TURN_SECRET_FILE`, `FT_ROUTER_ADDR`. Sin base de datos solo sirve el relay del
  PoC y `/health`.
- El relay del PoC 0 (`/poc/rooms/{room}`) sigue disponible para la pantalla de pruebas.

```sh
docker run -d --name ft-pg-test -e POSTGRES_PASSWORD=test -e POSTGRES_DB=ft_router_test \
  -p 127.0.0.1:55432:5432 postgres:17-alpine     # base de datos de los tests
cargo test -p ft-router                          # desde server/
docker build -t ft-router .                      # x86 en producción
```

## Estado: push (2026-09-22, `§106` M4)

- `PUT /v1/device/push` (`{"provider":"fcm","token":…}`) y `DELETE /v1/device/push`, firmados. El
  token se guarda cifrado (ChaCha20-Poly1305, `push.rs`) con una clave maestra que no está en la
  base de datos (`FT_PUSH_KEY_FILE`, secreto de Swarm, 32 bytes en base64). Migración `0002_push`.
- Un dispositivo **no conectado** se despierta cuando le llega una señal o un correo: FCM HTTP v1,
  mensaje de datos `{"t":"wake","s":"N"}` de prioridad alta y TTL 60 s, sin remitente ni contenido;
  `s` dice cuál de sus capacidades se usó (0–7, issue app#9). Como mucho un aviso cada 10 s por
  dispositivo y capacidad.
- **Ocho capacidades** (issue app#9, migración `0003_capabilities`): el registro puede traer
  `capability_hashes` con exactamente 8 hashes; la primera es la del dispositivo
  (`devices.capability_hash`). La app registra siempre 8, casi todas de relleno, para que el router
  no sepa cuántas sesiones ocultas hay. Un registro sin la lista (apps anteriores) sigue valiendo. Un token que FCM da por caducado se borra.
- FCM con una cuenta de servicio propia (`FT_FCM_SERVICE_ACCOUNT_FILE`) que solo puede enviar
  mensajes; el token OAuth se reutiliza hasta poco antes de caducar. Sin la clave o la cuenta, no se
  despierta a nadie.
- Tests: el cofre, el límite y FCM contra un Google falso que comprueba la firma RS256; en la API,
  guardar y borrar el token, despertar por señal y por correo, no despertar a quien está conectado y
  olvidar tokens caducados.

## Estado: producción (2026-09-22)

- **Límites** (`limits.rs`, `§91`): por ventana de 60 s, 600 peticiones firmadas por dispositivo,
  240 señales y correos por destinatario y 1200 registros, señales y correos por origen; por encima,
  429. Todo en memoria y sin logs. El origen es la última dirección de `X-Forwarded-For` (la que
  añade el balanceador de Hetzner; las anteriores las pone el cliente), guardada como hash con una
  sal nueva en cada arranque: ni en memoria hay IPs en claro.
- **Relay del PoC 0** apagado por defecto (era un relé abierto); solo con `FT_POC_RELAY=1`.
- `GET /version` responde la versión del crate. El despliegue la usa para saber cuándo sirve la
  nueva versión, porque durante la actualización progresiva `/health` lo sigue contestando la vieja.

## CI/CD (`.github/workflows/router.yml`, Plan `§105`)

- Cada PR pasa clippy y los tests con PostgreSQL.
- Cada push a `main` publica la imagen `ghcr.io/flickertalk/ft-router:canary`, que no se despliega.
- Cada tag `vX.Y.Z` (igual a `version` en `ft-router/Cargo.toml`):
  1. publica `:vX.Y.Z` y `:latest`;
  2. llama al webhook de Dokploy del stack del router, que solo puede redesplegar ese stack
     (secreto `DOKPLOY_ROUTER_WEBHOOK` del entorno `production`, solo para tags `v*`);
  3. espera hasta 5 minutos a que `api.flickertalk.com/version` responda la versión nueva.
- El stack despliega la imagen que diga `FT_ROUTER_IMAGE` en Dokploy. Hasta que el paquete de GHCR
  sea público sigue siendo la imagen compilada en los nodos (`infra/scripts/build-router.sh`).


## Estado: base de datos con WAL-G (2026-09-22, `§75`)

- `postgres/` construye `ghcr.io/flickertalk/postgres-walg`: PostgreSQL 17 con WAL-G. Con el
  directorio de datos vacío restaura la última copia base y reproduce el WAL; con datos, arranca y
  sigue archivando; sin `WALG_S3_PREFIX`, es un PostgreSQL normal (así corre hasta que exista el
  bucket). Copias base cada 24 h y solo las dos últimas (`§73`).
- El buzón es `UNLOGGED`: no entra en el WAL ni en las copias (`§19`). Si se restaura, vuelve
  vacío y los emisores reenvían lo pendiente (`§84`).
- `postgres/entrypoint.test.sh` prueba las tres decisiones del arranque con `wal-g` y `postgres`
  falseados; el CI además construye la imagen y comprueba que PostgreSQL arranca con el archivado
  activado.
