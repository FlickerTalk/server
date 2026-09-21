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
`DELETE /v1/mailbox/{blob_id}`; más adelante, quizá `POST /v1/signal/{device_id}`.

## Reglas

- **Nunca interpreta el contenido**: signaling y blobs del buzón son bytes opacos (`§14`). El blob
  temporal de signaling, si hace falta, vive solo en memoria, con TTL de 30–60 s (`§15`).
- Peticiones **firmadas**; `wake` y depositar en el buzón exigen una `route_capability` válida;
  rate limits y cuotas por destinatario (`§7`, `§34`, `§91`).
- **Logs** (`§71`): sin access logs, sin cuerpos, sin `device_id`, push tokens ni IPs. Métricas
  solo agregadas (`requests_total`, `wake_success_total`, `wake_failure_total`, `fcm_latency`,
  `apns_latency`, `http_errors`) y sin etiquetas identificativas.
- Los **reportes** de abuso no van aquí: infraestructura separada (`§36`).

## Pendiente de diseño

- Cómo obtiene el router la clave pública para verificar firmas (el plan solo fija
  `device_id = BLAKE3(public_identity_key)`).
- Buzón (`§19`): va en PostgreSQL (infraestructura en el repo privado), TTL definitivo,
  sealed sender (que el servidor no sepa quién envía), tamaño máximo y cuotas.
