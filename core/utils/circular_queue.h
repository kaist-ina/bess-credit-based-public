#ifndef BESS_UTILS_CIRCULAR_QUEUE_H_
#define BESS_UTILS_CIRCULAR_QUEUE_H_

#include "../packet.h"
#include "../pktbatch.h"

namespace bess {
namespace utils {

class CircularQueue {
 public:
  size_t cnt() const { return cnt_; }

  Packet *const *pkts() const { return pkts_; }
  Packet **pkts() { return pkts_; }
  Packet *head() const { return pkts_[head_]; }
  Packet *tail() const { return pkts_[tail_]; }

  void clear() {
    cnt_ = 0;
    head_ = 0;
    tail_ = 0;
  }

  void push_back(Packet *pkt) { 
    if (cnt_ >= kMaxBurst - 1) {
      LOG(INFO) << "Queue Full!!";
      return;
    }

    pkts_[tail_] = pkt;
    tail_ = (tail_ + 1) % kMaxBurst;
    cnt_++;
  }

  inline Packet *peek_front() const { return pkts_[head_]; };

  void pop_front() {
    if (!cnt_)
      return;
    head_ = (head_ + 1) % kMaxBurst;
    cnt_--;
  }

  bool empty() { return (cnt_ == 0); }

  bool full() { return (cnt_ >= kMaxBurst - 1); }

  void Copy(const CircularQueue *src) {
    cnt_ = src->cnt_;
    bess::utils::CopyInlined(pkts_, src->pkts_, cnt_ * sizeof(Packet *));
  }

  int checkIntegrity(bool (*predicate)(bess::Packet *)) { 
    for (size_t i = 0; i < cnt_; i++) {
      size_t idx = (head_ + i) % kMaxBurst;
      if (!predicate(pkts_[idx])) {
        LOG(INFO) << "Integrity check failure.";
        return idx;
      }
    }
    return -1;
  }

  static const size_t kMaxBurst = 8192;

 private:
  size_t cnt_;
  Packet *pkts_[kMaxBurst];
  size_t head_;
  size_t tail_;
};
static_assert(std::is_pod<CircularQueue>::value, "CircularQueue is not a POD Type");
}
}


#endif