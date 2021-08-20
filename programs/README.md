# NDNph Linux Examples

This directory contains several self-contained programs using NDNph.
All commands accept `-h` command line flag for usage instructions.

## List of Programs

`ndnph-keychain` performs basic key and certificate operations.

[`ndnph-ndncertclient`](ndncertclient.md) is a NDNCERT client.

`ndnph-pingclient` is an ndnping client.

## Environment Variables

These programs can be configured through environment variables.

`NDNPH_KEYCHAIN` is the filesystem path of KeyChain storage.
This is required in programs that access the persistent KeyChain.

`NDNPH_UPLINK_MEMIF` enables libmemif transport.
It should be set to the socket name of libmemif transport.
Note that libmemif generally requires sudo privilege.
You can create a memif face in NDN-DPDK with this locator:

```jsonc
{
  "scheme": "memif",
  "socketName": "same value as NDNPH_UPLINK_MEMIF environ",
  "id": 0,
  "dataroom": /* same value as NDNPH_UPLINK_MTU environ */
}
```

`NDNPH_UPLINK_UDP_LISTEN=1` enables UDP listen mode.

`NDNPH_UPLINK_UDP` specifies IPv4 address of the uplink router.
The default is `127.0.0.1`, which connects to local NFD over UDP.

`NDNPH_UPLINK_UDP_PORT` specifies UDP port.
It is used as local port in listen mode, or remote port in tunnel mode.
The default is `6363`.

`NDNPH_UPLINK_MTU` enables fragmentation and reassembly.
It should be set to a positive number between 64 and 9000 that is the maximum NDNLPv2 frame size.
