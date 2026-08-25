add_executable(LocalTimeMathTest
  LocalTimeMathTest.cpp
)

target_link_libraries(LocalTimeMathTest PRIVATE
  crosspoint_test_common
  GTest::gtest_main
)

gtest_discover_tests(LocalTimeMathTest)
