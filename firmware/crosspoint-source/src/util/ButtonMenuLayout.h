#pragma once

namespace button_menu {

struct Layout {
  int first = 0;
  int count = 0;
  int capacity = 0;
  int topInset = 0;
  int rowHeight = 0;
  int rowSpacing = 0;

  constexpr int rowStep() const { return rowHeight + rowSpacing; }
};

// Return the page that contains selectedIndex. Keeping this calculation in one
// host-testable helper ensures rendering and Home's touch hit-testing use the
// same page window.
constexpr Layout pageFor(const int itemCount, const int selectedIndex, const int viewportHeight,
                         const int rowHeight, const int rowSpacing, const int topInset = 0) {
  Layout layout;
  layout.topInset = topInset > 0 ? topInset : 0;
  layout.rowHeight = rowHeight > 0 ? rowHeight : 1;
  layout.rowSpacing = rowSpacing > 0 ? rowSpacing : 0;
  if (itemCount <= 0) return layout;

  const int availableHeight = viewportHeight > layout.topInset ? viewportHeight - layout.topInset : 0;
  const int step = layout.rowStep();
  // The last visible row has no trailing gap, hence +rowSpacing here.
  layout.capacity = (availableHeight + layout.rowSpacing) / step;
  if (layout.capacity < 1) layout.capacity = 1;

  int safeSelectedIndex = selectedIndex;
  if (safeSelectedIndex < 0) safeSelectedIndex = 0;
  if (safeSelectedIndex >= itemCount) safeSelectedIndex = itemCount - 1;
  layout.first = (safeSelectedIndex / layout.capacity) * layout.capacity;
  const int remaining = itemCount - layout.first;
  layout.count = remaining < layout.capacity ? remaining : layout.capacity;
  return layout;
}

constexpr int itemAtVisibleRow(const Layout& layout, const int visibleRow) {
  return visibleRow >= 0 && visibleRow < layout.count ? layout.first + visibleRow : -1;
}

}  // namespace button_menu
