#ifndef BESS_UTILS_XPASS_H_
#define BESS_UTILS_XPASS_H_

#include "../xpass_config.h"
#include <stdint.h>
#include <type_traits>

namespace bess {
namespace utils {

struct[[gnu::packed]] Xpass {
  enum XPassPacketType : uint8_t {
    kCredit = 0x00,
    kData = 0x01,
    kCreditRequest = 0x02,
    kCreditStop = 0x03,
    kNack = 0x04,
    kCreditStopAck = 0x05,
  };

  be32_t credit_seq;
  be32_t orig_seqno;
  be32_t credit_sent_time;
  uint8_t packet_type;
  uint8_t xpass_flag;
};

const uint8_t XPASS_TCP_OPTION_TYPE = 0x11;
const uint16_t XPASS_UDP_SRC_PORT = 19010;
const uint16_t XPASS_UDP_DST_PORT = 19010;

struct [[gnu::packed]] XpassTcpOption {
  uint8_t tcp_option_type{XPASS_TCP_OPTION_TYPE};
  uint8_t tcp_option_len{sizeof(XpassTcpOption)};
  struct Xpass xpass;
};


const char GDX_DSCP_CREDIT = 0x0A;
const char GDX_DSCP_REACTIVE = 0x08;
const char GDX_DSCP_PROACTIVE = 0x0C;
const char GDX_DSCP_EXPPASS = 0x0E; // For Control Packet

static_assert(sizeof(XpassTcpOption) % 4 == 0, "XpassTcpOption is incorrect");
static_assert(std::is_pod<Xpass>::value, "not a POD type");
static_assert(sizeof(Xpass) == XPASS_BYTES, "struct Xpass is incorrect");

}  // namespace utils
}  // namespace bess

#endif  // BESS_UTILS_XPASS_H_
