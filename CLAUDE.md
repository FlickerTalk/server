# server/

Backend de FlickerTalk. Contiene un único servicio: `ft-router/`.

El backend **no es un servidor de chat** (`Plan.md §1`). Antes de añadir cualquier dato,
endpoint o servicio aquí se aplica `§100`: si no hace falta guardarlo, no se guarda; si hace
falta, se minimiza, se protege y se borra cuanto antes. Nada de Redis, Kafka, RabbitMQ,
Elasticsearch, MongoDB ni Kubernetes (`§75`).
