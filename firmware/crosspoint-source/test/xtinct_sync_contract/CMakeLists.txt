add_executable(xtinct_sync_contract_tests XtinctSyncContractTest.cpp)
target_link_libraries(xtinct_sync_contract_tests PRIVATE crosspoint_test_common GTest::gtest_main)
gtest_discover_tests(xtinct_sync_contract_tests)

add_test(
  NAME xtinct_outbox_memory_source_contract
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/verify_outbox_memory_contract.py
)
