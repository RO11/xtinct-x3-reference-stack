#include <cstdint>

#include "src/util/BoundedResponseBuffer.h"

int main() {
  xtinct::network::BoundedResponseBuffer buffer(48U * 1024U);
  const uint8_t bytes[] = {'o', 'k'};
  if (!buffer.reserve(8192) || !buffer.append(bytes, sizeof(bytes))) return 1;
  if (buffer.size() != sizeof(bytes) || buffer.data()[buffer.size()] != '\0') return 2;
  buffer.release();
  return buffer.data() == nullptr && buffer.size() == 0 ? 0 : 3;
}
