# NDNph Linux Examples

This directory contains several self-contained programs using NDNph.
All commands accept `-h` command line flag for usage instructions.

Environment variables:

* `NDNPH_UPLINK_UDP`: IPv4 address of the uplink router.
  Default to `127.0.0.1`.
* `NDNPH_KEYCHAIN`: filesystem path of KeyChain storage.
  This is required in programs that access the persistent KeyChain.
