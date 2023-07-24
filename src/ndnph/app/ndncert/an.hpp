#ifndef NDNPH_APP_NDNCERT_AN_HPP
#define NDNPH_APP_NDNCERT_AN_HPP

#include "../../packet/component.hpp"
#include "../../tlv/value.hpp"

namespace ndnph {
namespace ndncert {

/** @brief TLV-TYPE assigned numbers. */
namespace TT {
enum {
  CaPrefix = 0x81,
  CaInfo = 0x83,
  ParameterKey = 0x85,
  ParameterValue = 0x87,
  CaCertificate = 0x89,
  MaxValidityPeriod = 0x8B,
  ProbeResponse = 0x8D,
  MaxSuffixLength = 0x8F,
  EcdhPub = 0x91,
  CertRequest = 0x93,
  Salt = 0x95,
  RequestId = 0x97,
  Challenge = 0x99,
  Status = 0x9B,
  InitializationVector = 0x9D,
  EncryptedPayload = 0x9F,
  SelectedChallenge = 0xA1,
  ChallengeStatus = 0xA3,
  RemainingTries = 0xA5,
  RemainingTime = 0xA7,
  IssuedCertName = 0xA9,
  ErrorCode = 0xAB,
  ErrorInfo = 0xAD,
  AuthenticationTag = 0xAF,
  CertToRevoke = 0xB1,
  ProbeRedirect = 0xB3,
};
using namespace ndnph::TT;
} // namespace TT

/** @brief Return 'CA' component. */
inline Component
getCaComponent() {
  static const uint8_t tlv[]{0x08, 0x02, 'C', 'A'};
  static const Component comp = Component::constant(tlv, sizeof(tlv));
  return comp;
}

/** @brief Return 'INFO' component. */
inline Component
getInfoComponent() {
  static const uint8_t tlv[]{0x08, 0x04, 'I', 'N', 'F', 'O'};
  static const Component comp = Component::constant(tlv, sizeof(tlv));
  return comp;
}

/** @brief Return 'PROBE' component. */
inline Component
getProbeComponent() {
  static const uint8_t tlv[]{0x08, 0x05, 'P', 'R', 'O', 'B', 'E'};
  static const Component comp = Component::constant(tlv, sizeof(tlv));
  return comp;
}

/** @brief Return 'NEW' component. */
inline Component
getNewComponent() {
  static const uint8_t tlv[]{0x08, 0x03, 'N', 'E', 'W'};
  static const Component comp = Component::constant(tlv, sizeof(tlv));
  return comp;
}

/** @brief Return 'CHALLENGE' component. */
inline Component
getChallengeComponent() {
  static const uint8_t tlv[]{0x08, 0x09, 'C', 'H', 'A', 'L', 'L', 'E', 'N', 'G', 'E'};
  static const Component comp = Component::constant(tlv, sizeof(tlv));
  return comp;
}

/** @brief Status assigned numbers. */
namespace Status {
enum {
  BEFORE_CHALLENGE = 0,
  CHALLENGE = 1,
  PENDING = 2,
  SUCCESS = 3,
  FAILURE = 4,
};
} // namespace Status

/** @brief ErrorCode assigned numbers. */
namespace ErrorCode {
enum {
  BadInterestFormat = 1,
  BadParameterFormat = 2,
  BadSignature = 3,
  InvalidParameters = 4,
  NameNotAllowed = 5,
  BadValidityPeriod = 6,
  OutOfTries = 7,
  OutOfTime = 8,
  NoAvailableName = 9,
};
} // namespace ErrorCode

namespace challenge_consts {

inline tlv::Value
nop() {
  static auto v = tlv::Value::fromString("nop");
  return v;
}

inline tlv::Value
possession() {
  static auto v = tlv::Value::fromString("possession");
  return v;
}

inline tlv::Value
issuedcert() {
  static auto v = tlv::Value::fromString("issued-cert");
  return v;
}

inline tlv::Value
nonce() {
  static auto v = tlv::Value::fromString("nonce");
  return v;
}

inline tlv::Value
proof() {
  static auto v = tlv::Value::fromString("proof");
  return v;
}

} // namespace challenge_consts

} // namespace ndncert
} // namespace ndnph

#endif // NDNPH_APP_NDNCERT_AN_HPP
