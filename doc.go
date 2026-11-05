// Package pki issues the certificates of a Norca cluster: the cluster CA,
// the identities of servers and clients (the names Norca verifies), SPIFFE
// IDs, intermediate CAs, and the name-constrained node CA that signs the
// certificates of nodes that join by themselves.
//
// It is shared by the deployer, which creates the cluster CA and the node
// CA, and by the node scaling operator, which signs the certificates of the
// nodes it creates with the node CA. It depends on the standard library
// only.
package pki
