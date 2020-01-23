#ifndef NDNPH_AN_HPP
#define NDNPH_AN_HPP

namespace ndnph {

/** @brief TLV-TYPE assigned numbers. */
namespace TT {
enum
{
  Name = 0x07,
  GenericNameComponent = 0x08,
  ImplicitSha256DigestComponent = 0x01,
  ParametersSha256DigestComponent = 0x02,

  Interest = 0x05,
  CanBePrefix = 0x21,
  MustBeFresh = 0x12,
  ForwardingHint = 0x1E,
  Nonce = 0x0A,
  InterestLifetime = 0x0C,
  HopLimit = 0x22,
  AppParameters = 0x24,
  ISigInfo = 0x2C,
  ISigValue = 0x2E,

  Data = 0x06,
  MetaInfo = 0x14,
  ContentType = 0x18,
  FreshnessPeriod = 0x19,
  FinalBlockId = 0x1A,
  Content = 0x15,
  DSigInfo = 0x16,
  DSigValue = 0x17,

  SigType = 0x1B,
  KeyLocator = 0x1C,
  KeyDigest = 0x1D,
  SigNonce = 0x26,
  SigTime = 0x28,
  SigSeqNum = 0x2A,

  Delegation = 0x1F,
  Preference = 0x1E,

  LpPacket = 0x64,
  LpPayload = 0x50,
  PitToken = 0x62,
  Nack = 0x0320,
  NackReason = 0x0321,
};
} // namespace TT

/** @brief SignatureType assigned numbers. */
namespace SigType {
enum
{
  Sha256 = 0x00,
  Sha256WithRsa = 0x01,
  Sha256WithEcdsa = 0x03,
  HmacWithSha256 = 0x04,
};
} // namespace SigType

} // namespace ndnph

#endif // NDNPH_AN_HPP
