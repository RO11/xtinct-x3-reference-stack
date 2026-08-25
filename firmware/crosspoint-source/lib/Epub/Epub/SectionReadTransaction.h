#pragma once

namespace epub::detail {

// Restores a shared read/write section handle to its append cursor during
// normal return and exception unwinding. `restored` becomes true only after a
// successful seek; Section uses false to abandon the temp transaction instead
// of risking a later write at an unknown offset.
template <typename File>
class FileCursorRestoreGuard final {
 public:
  FileCursorRestoreGuard(File& file, const unsigned long position, bool& restored) noexcept
      : file_(file), position_(position), restored_(restored) {
    restored_ = false;
  }
  ~FileCursorRestoreGuard() noexcept {
    if (active_) restored_ = seekNoThrow();
  }
  bool restore() noexcept {
    if (!active_) return restored_;
    active_ = false;
    restored_ = seekNoThrow();
    return restored_;
  }

 private:
  bool seekNoThrow() noexcept {
#if defined(__cpp_exceptions)
    try {
      return file_.seek(position_);
    } catch (...) {
      return false;
    }
#else
    return file_.seek(position_);
#endif
  }

  File& file_;
  unsigned long position_;
  bool& restored_;
  bool active_ = true;
};

}  // namespace epub::detail
