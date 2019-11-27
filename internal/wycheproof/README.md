This package runs a set of the Wycheproof tests provided by
https://github.com/google/wycheproof.

The tests being run are in https://github.com/google/wycheproof/tree/master/testvectors.

The structs for each type of test are generated from the
schemas provided in https://github.com/google/wycheproof/tree/master/schemas.
These structs were generated using https://github.com/a-h/generate.

To update the version of the wycheproof repository that is being
used for testing, change the version directly in the TestMain for
this package.