# SoftHSM test patch provenance

`cloudhsm-aes-gcm.patch` applies to `src/lib/SoftHSM.cpp` from
[OpenDNSSEC SoftHSMv2](https://github.com/opendnssec/SoftHSMv2), tag `2.6.1`,
as selected by `tests/consumers/Dockerfile.daemon.softhsm2-patched`.
The patch includes upstream source context around project-added alias lines;
it does not change the provider version or its general behavior beyond that
test-specific mechanism alias.

The upstream source is under its [BSD-style two-clause license](https://github.com/softhsm/SoftHSMv2/blob/2.6.1/LICENSE),
reproduced here as [LICENSE-SoftHSM](LICENSE-SoftHSM) for the patch context.
The Docker test image copies the upstream `LICENSE` from the cloned source into
`/usr/local/share/licenses/softhsm2/LICENSE` alongside the patched provider.
The patch and provider are test material; neither is included in the eight
project source crates or ordinary proxy release bundles.
