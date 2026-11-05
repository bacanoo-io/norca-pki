# norca-pki

The certificates of a Norca cluster, as a small Go module with no dependency
beyond the standard library:

- the cluster CA (`NewCA`, `LoadCA`, `ParseCA`), ECDSA P-256, with the SPIFFE
  trust domain as a URI SAN;
- the identities Norca verifies: `ServerIdentity` (`server.<region>.norca`)
  and `ClientIdentity` (`client.<region>.norca`), with SPIFFE IDs
  (`TrustDomain`, `SPIFFEID`, `SPIFFEIDs`);
- issuing (`Issue`, `IssueIntermediate`) and reuse checks (`Reusable`);
- the **node CA** (`IssueNodeCA`): an intermediate with a path length of zero,
  name-constrained to the client names of one region, `localhost`,
  `127.0.0.1` and the trust domain. It can sign the certificates of nodes and
  nothing else: not a server, not another region, not a foreign name.

It is shared by the [deployer](https://github.com/bacanoo-io/norca-deployer),
which creates the cluster CA and the node CA, and by the node scaling
operator, which signs the certificates of the nodes it creates. The code
comes from the `pkg/pki` package of the deployer, with its history.

```go
import "github.com/bacanoo-io/norca-pki"

ca, err := pki.NewCA("Example", 10, trustDomain)
nodeCA, err := ca.IssueNodeCA("node CA eu", "eu", 180*24*time.Hour, trustDomain)
```

## Development

```shell
make test      # the tests
make lint      # golangci-lint v2 with .golangci.yml
make fmt       # gofmt of the toolchain in go.mod
```

Commits are signed off (`git commit -s`).
