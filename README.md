# external-dns-webhook

[external-dns](https://github.com/kubernetes-sigs/external-dns) webhook provider for
**Nubulus Network DNS**. It runs as a sidecar of external-dns and keeps the records of your
`Ingress`, `Service` and `Gateway` resources in your Nubulus zones.

## Requirements

- One or more zones in your account, **active** (verified).
- An **application token** with role `member`, created in the panel at
  `/dashboard/account/tokens`. It gives a `client_id` and a `client_secret`; the secret is shown
  once. A personal access token from the identity provider does not work.

## Install

```sh
kubectl create secret generic nubulus-credentials \
  --from-literal=client-id=YOUR_CLIENT_ID \
  --from-literal=client-secret=YOUR_CLIENT_SECRET

helm repo add external-dns https://kubernetes-sigs.github.io/external-dns/
helm upgrade --install external-dns external-dns/external-dns -f examples/values.yaml
```

See [`examples/values.yaml`](examples/values.yaml). Set `txtOwnerId` to a value unique per
cluster.

## Configuration

| Variable | Default | |
|---|---|---|
| `NUBULUS_CLIENT_ID` | | required |
| `NUBULUS_CLIENT_SECRET` | | required |
| `WEBHOOK_LISTEN` | `127.0.0.1:8888` | provider API, reachable by external-dns only |
| `HEALTH_LISTEN` | `0.0.0.0:8080` | `/healthz`, `/readyz` |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |

## Behaviour

- **Zones**: every active zone of the account is offered to external-dns. Narrow it down with
  `domainFilters`. A name is written to the most specific zone that contains it
  (`x.k8s.example.com` goes to `k8s.example.com` if you have both).
- **Record types**: A, AAAA, CNAME, TXT, MX, SRV, CAA, NS (below the apex) and others. Enable the
  extra ones with `--managed-record-types`. SOA, the apex NS and DNSSEC types are managed by the
  platform and never touched.
- **TTL**: 300 s when not set; values are clamped to 60–604800 s.
- **Not supported**: routing policies (`set-identifier`), CNAME at the zone apex. Such endpoints are
  ignored with a warning in the log.
- **Errors**: a batch is applied record by record; one failing record does not stop the others.
  Temporary failures are answered with a 5xx so external-dns retries.

## Development

```sh
go test ./...
docker build -t external-dns-webhook .
```

Releases are built from `v*` tags and published to `ghcr.io/nubulus-network/external-dns-webhook`
for amd64 and arm64.

## License

MPL-2.0
