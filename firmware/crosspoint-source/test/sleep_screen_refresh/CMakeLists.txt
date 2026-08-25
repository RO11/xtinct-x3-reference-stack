add_executable(sleep_screen_refresh_tests SleepScreenRefreshPolicyTest.cpp)
target_include_directories(sleep_screen_refresh_tests PRIVATE ${REPO_ROOT}/lib/hal)
target_link_libraries(sleep_screen_refresh_tests PRIVATE crosspoint_test_common GTest::gtest_main)
gtest_discover_tests(sleep_screen_refresh_tests)

add_test(
  NAME sleep_screen_refresh_source_contract
  COMMAND ${Python3_EXECUTABLE} -B ${CMAKE_CURRENT_SOURCE_DIR}/verify_source_contract.py
)
