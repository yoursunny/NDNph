# NDNph Linux Examples

This directory contains several self-contained programs using NDNph.
All commands accept `-h` command line flag for usage instructions.

## List of Programs

`ndnph-keychain` performs basic key and certificate operations.

[`ndnph-ndncertclient`](ndncertclient.md) is a NDNCERT client.

`ndnph-pingclient` is an ndnping client.

## Environment Variables

These programs can be configured through environment variables defined in `cli-common.hpp`.

`NDNPH_KEYCHAIN` is the filesystem path of KeyChain storage.
This is required in programs that access the persistent KeyChain.

`NDNPH_UPLINK_MEMIF` enables libmemif transport.
It should be set to the socket name of libmemif transport.
Note that libmemif generally requires sudo privilege.
You can create a memif face in NDN-DPDK with this locator:

```json
{
  "scheme": "memif",
  "socketName": "same value as NDNPH_UPLINK_MEMIF environ",
  "id": 0
}
```

`NDNPH_UPLINK_UDP` specifies IPv4 address of the uplink router.
The default is `127.0.0.1`, which connects to local NFD over UDP.
