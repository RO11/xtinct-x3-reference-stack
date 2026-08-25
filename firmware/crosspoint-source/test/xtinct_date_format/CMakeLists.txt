add_executable(XtinctDateFormatTest
  XtinctDateFormatTest.cpp
)

target_link_libraries(XtinctDateFormatTest PRIVATE
  crosspoint_test_common
  GTest::gtest_main
)

gtest_discover_tests(XtinctDateFormatTest)
