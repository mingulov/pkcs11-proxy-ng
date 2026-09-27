# Staging publish probe

This dependency-free crate checks staging registry publication separately from
the eight production packages. Its generated version includes the CI run ID and
attempt. It is never published to crates.io.
