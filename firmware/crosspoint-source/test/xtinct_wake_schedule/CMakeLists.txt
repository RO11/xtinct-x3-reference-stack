add_executable(XtinctWakeScheduleTest
  XtinctWakeScheduleTest.cpp
)

target_link_libraries(XtinctWakeScheduleTest PRIVATE
  crosspoint_test_common
  GTest::gtest_main
)
target_include_directories(XtinctWakeScheduleTest PRIVATE ${REPO_ROOT}/lib/hal)

gtest_discover_tests(XtinctWakeScheduleTest)
