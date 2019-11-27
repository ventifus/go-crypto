This package runs a set of the Wycheproof tests provided by
https://github.com/google/wycheproof.

The tests in crypto/internal/wycheproof/vendor/testvectors are
copied directly from https://github.com/google/wycheproof/tree/master/testvectors.

The structs for each type of test are generated from the
schemas provided in https://github.com/google/wycheproof/tree/master/schemas
and copied into crypto/internal/wycheproof/vendor/schemas for
reference.

TODO: Add information for how to re-generate the structs from the schemas

To update the vendor directory, run the following in the root
directory of your local x/crypto branch, replacing the version of
github.com/google/wycheproof in your module cache (`$GOPATH/pkg/mod/`)
with the one that was just downloaded.

```
go get github.com/google/wycheproof@latest
sudo rm -rf internal/wycheproof/vendor
mkdir -p internal/wycheproof/vendor
cp -r $GOPATH/pkg/mod/github.com/google/wycheproof@v0.0.0-20191126014559-06e5e105eeb9/testvectors internal/wycheproof/vendor/testvectors
cp -r $GOPATH/pkg/mod/github.com/google/wycheproof@v0.0.0-20191126014559-06e5e105eeb9/schemas internal/wycheproof/vendor/schemas
cp $GOPATH/pkg/mod/github.com/google/wycheproof@v0.0.0-20191126014559-06e5e105eeb9/LICENSE internal/wycheproof/vendor
```