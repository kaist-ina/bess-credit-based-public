#ifndef BESS_MODULES_TSO_H_
#define BESS_MODULES_TSO_H_

#include "../module.h"
#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Tcp;
using bess::utils::be16_t;
using bess::utils::be32_t;

class TSO final : public Module {
public:
  TSO() {}

  static const gate_idx_t kNumIGates = 1;
  static const gate_idx_t kNumOGates = 1;

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;
  void DoTso(Context *ctx, bess::Packet *pkt, bess::PacketBatch *&new_batch);
  inline void PushBatch(Context *ctx, bess::Packet *pkt, bess::PacketBatch *&new_batch);
};

#endif // BESS_MODULES_TSO_H_