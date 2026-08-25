#include <gtest/gtest.h>

#include "src/util/ButtonMenuLayout.h"

TEST(ButtonMenuLayout, PagesSevenLyraRowsBeforeTheHintBar) {
  // X3 portrait is 528x792. Lyra's menu starts at y=314; after the 40px
  // button-hint bar and 16px bottom spacing, the true viewport is 422px.
  constexpr auto page = button_menu::pageFor(7, 6, 422, 64, 8);
  static_assert(page.capacity == 5);
  static_assert(page.first == 5);
  static_assert(page.count == 2);
  EXPECT_EQ(button_menu::itemAtVisibleRow(page, 1), 6);
  EXPECT_LE(page.topInset + (page.count - 1) * page.rowStep() + page.rowHeight, 422);
}

TEST(ButtonMenuLayout, KeepsClassicTopInsetAndTouchMappingAligned) {
  constexpr auto firstPage = button_menu::pageFor(7, 4, 300, 45, 8, 10);
  static_assert(firstPage.capacity == 5);
  static_assert(firstPage.first == 0);
  EXPECT_EQ(button_menu::itemAtVisibleRow(firstPage, 4), 4);

  constexpr auto settingsPage = button_menu::pageFor(7, 6, 300, 45, 8, 10);
  static_assert(settingsPage.first == 5);
  static_assert(settingsPage.count == 2);
  EXPECT_EQ(button_menu::itemAtVisibleRow(settingsPage, 1), 6);
  EXPECT_EQ(button_menu::itemAtVisibleRow(settingsPage, 2), -1);
}

TEST(ButtonMenuLayout, HandlesEmptyAndTooSmallViewportsSafely) {
  constexpr auto empty = button_menu::pageFor(0, 0, 300, 45, 8);
  static_assert(empty.count == 0);
  static_assert(empty.capacity == 0);

  constexpr auto tiny = button_menu::pageFor(7, 6, 1, 64, 8);
  static_assert(tiny.capacity == 1);
  static_assert(tiny.first == 6);
  static_assert(tiny.count == 1);
}
