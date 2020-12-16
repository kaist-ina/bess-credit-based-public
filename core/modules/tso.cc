#include "tso.h"
#include "../utils/checksum.h"

const int MTU = 8984;
using bess::utils::Udp;

void TSO::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  int cnt = batch->cnt();
  bess::PacketBatch *new_batch = ctx->task->AllocPacketBatch();
  
  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];
    DoTso(ctx, pkt, new_batch);
  }

  RunNextModule(ctx, new_batch);
}

inline void TSO::PushBatch(Context *ctx, bess::Packet *pkt, bess::PacketBatch *&new_batch) {
  if (unlikely(new_batch->full())) {
    RunNextModule(ctx, new_batch);
    new_batch = ctx->task->AllocPacketBatch();
  }
  new_batch->add(pkt);
}

void TSO::DoTso(Context *ctx, bess::Packet *pkt, bess::PacketBatch *&new_batch) {		
  uint16_t ip_offset, l4_offset, payload_offset;
  uint32_t seq;

  int org_frame_len = pkt->total_len();
  int max_seg_size;
  int seg_size;

  assert(org_frame_len);

  if (org_frame_len <= MTU) {
    PushBatch(ctx, pkt, new_batch);
    return;
  }

  //get the headers of the packet
  Ethernet *eth = pkt->head_data<Ethernet *>();
	
  //[SKIP] check 802.1Q tag
  if (unlikely(eth->ether_type != be16_t(Ethernet::Type::kIpv4))) {
    PushBatch(ctx, pkt, new_batch);
    return;
  }

  Ipv4 *iph = reinterpret_cast<Ipv4 *>(eth + 1);
  size_t ip_bytes = (iph->header_length) << 2;
  ip_offset = reinterpret_cast<char *>(iph) - reinterpret_cast<char *>(eth);
  l4_offset = ip_offset + ip_bytes;

  if (iph->protocol == Ipv4::Proto::kTcp) {
    Tcp *tcph = reinterpret_cast<Tcp *>(reinterpret_cast<char *>(iph) + ip_bytes);
    size_t tcp_bytes = (tcph->offset) << 2;
    payload_offset = l4_offset + tcp_bytes;

    seq = tcph->seq_num.value();
    max_seg_size = MTU - payload_offset;

    for (int i = payload_offset; i < org_frame_len; i += max_seg_size) {
      Ipv4 *new_iph;
      Tcp *new_tcph;
      uint16_t new_ip_total_len;

      bool first = (i == payload_offset);
      bool last = (i + max_seg_size >= org_frame_len);

      seg_size = std::min(org_frame_len - i, max_seg_size);

      bess::Packet *new_pkt = current_worker.packet_pool()->Alloc();
      char *p = static_cast<char *>(new_pkt->buffer()) + SNBUF_HEADROOM;
      new_pkt->set_data_off(SNBUF_HEADROOM);

      new_iph = reinterpret_cast<Ipv4 *>(p + ip_offset);
      new_tcph = reinterpret_cast<Tcp *>(p + l4_offset);

      new_pkt->set_total_len(payload_offset + seg_size);
      new_pkt->set_data_len(payload_offset + seg_size);
      bess::utils::Copy(p, pkt->head_data(), payload_offset);
      bess::utils::Copy(p + payload_offset, pkt->head_data(i), seg_size);

      new_ip_total_len = (payload_offset - ip_offset) + seg_size;

      new_iph->length = be16_t(new_ip_total_len);
      new_tcph->seq_num = be32_t(seq);

      seq += seg_size;

      // CWR only for the first packet
      if (!first) {
        new_tcph->flags &= 0x7f;	
      }

      // PSH and FIN only for the last packet
      if (!last) {
        new_tcph->flags &= 0xf6;
      }

      new_tcph->checksum = CalculateIpv4TcpChecksum(*new_iph, *new_tcph);
      new_iph->checksum = CalculateIpv4Checksum(*new_iph);

      assert(new_pkt->total_len());
      PushBatch(ctx, new_pkt, new_batch);
    }

  } else if (iph->protocol == Ipv4::Proto::kUdp) {
    Udp *udph = reinterpret_cast<Udp *>(reinterpret_cast<char *>(iph) + ip_bytes);
    payload_offset = l4_offset + sizeof(Udp);
    int frame_len = l4_offset + udph->length.value(); // org_frame_len might be different from frame_len!
    max_seg_size = MTU - payload_offset;

    for (int i = payload_offset; i < frame_len; i += max_seg_size) {
      Ipv4 *new_iph;
      Udp *new_udph;
      uint16_t new_ip_total_len;

      seg_size = std::min(org_frame_len - i, max_seg_size);

      bess::Packet *new_pkt = current_worker.packet_pool()->Alloc();
      char *p = static_cast<char *>(new_pkt->buffer()) + SNBUF_HEADROOM;
      new_pkt->set_data_off(SNBUF_HEADROOM);

      new_iph = reinterpret_cast<Ipv4 *>(p + ip_offset);
      new_udph = reinterpret_cast<Udp *>(p + l4_offset);

      new_pkt->set_total_len(payload_offset + seg_size);
      new_pkt->set_data_len(payload_offset + seg_size);
      bess::utils::Copy(p, pkt->head_data(), payload_offset);
      bess::utils::Copy(p + payload_offset, pkt->head_data(i), seg_size);

      new_ip_total_len = (payload_offset - ip_offset) + seg_size;

      new_iph->length = be16_t(new_ip_total_len);
      new_udph->length = be16_t(seg_size + sizeof(Udp));

      new_udph->checksum = CalculateIpv4UdpChecksum(*new_iph, *new_udph);
      new_iph->checksum = CalculateIpv4Checksum(*new_iph);

      assert(new_pkt->total_len());
      PushBatch(ctx, new_pkt, new_batch);
    }
  } else {
    PushBatch(ctx, pkt, new_batch);
    return;
  }

  bess::Packet::Free(pkt);
}

ADD_MODULE(TSO, "tso", "split large-sized TCP segments into small packets")