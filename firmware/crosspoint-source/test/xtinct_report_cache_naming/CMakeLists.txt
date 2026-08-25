add_executable(XtinctReportCacheNamingTest
  XtinctReportCacheNamingTest.cpp
)

target_link_libraries(XtinctReportCacheNamingTest PRIVATE
  crosspoint_test_common
  GTest::gtest_main
)

gtest_discover_tests(XtinctReportCacheNamingTest)
