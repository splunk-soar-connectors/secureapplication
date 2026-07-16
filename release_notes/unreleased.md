**Unreleased**

* Verify Secure Application controller TLS certificates by default for API and OAuth requests.
* Encrypt cached OAuth access tokens in connector state and discard legacy cleartext tokens.
* Require positive integer policy identifiers before constructing controller request paths.
* Bound policy listing pagination and stop when the controller returns an empty page.
