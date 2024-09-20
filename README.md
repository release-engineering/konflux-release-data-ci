# konflux-release-data-ci
Config for building CI worker image for konflux-release-data repo

## TODO - Need
* Fix SBOM issues related to the ruby gem install
* Ensure existing CI tests can run in this image
* Try running mkdocs CI jobs and update image as necssesary

## TODO - Should Do
* Convert to UBI
  * Setup prefetch for tox (pip)
* Setup prefetch for rpms
* Enable konflux-release-data integration test
  * Migrate to internal cluster
  * Setup integration test that clones krd repo and runs tox
    * Bonus points for running pyxis integration tests
