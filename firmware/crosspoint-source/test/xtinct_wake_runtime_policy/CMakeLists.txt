add_executable(XtinctWakeRuntimePolicyTest
  XtinctWakeRuntimePolicyTest.cpp
)

target_link_libraries(XtinctWakeRuntimePolicyTest PRIVATE
  crosspoint_test_common
  GTest::gtest_main
)

gtest_discover_tests(XtinctWakeRuntimePolicyTest)
