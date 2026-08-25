add_executable(BoundedUtf8WrapTest
  BoundedUtf8WrapTest.cpp
)

target_link_libraries(BoundedUtf8WrapTest PRIVATE
  crosspoint_test_common
  GTest::gtest_main
)

gtest_discover_tests(BoundedUtf8WrapTest)
