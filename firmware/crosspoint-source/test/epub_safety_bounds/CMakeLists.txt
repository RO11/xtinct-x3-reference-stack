add_executable(epub_safety_bounds_tests
  EpubSafetyBoundsTest.cpp
  PageDecodeDependencyStubs.cpp
  ${REPO_ROOT}/lib/Epub/Epub/Page.cpp
  ${REPO_ROOT}/lib/expat/xmlparse.c
  ${REPO_ROOT}/lib/expat/xmlrole.c
  ${REPO_ROOT}/lib/expat/xmltok.c
)
target_include_directories(epub_safety_bounds_tests BEFORE PRIVATE
  stubs
  ${REPO_ROOT}/lib/Epub
  ${REPO_ROOT}/lib/Serialization
  ${REPO_ROOT}/lib/expat
)
target_compile_definitions(epub_safety_bounds_tests PRIVATE XML_GE=0 XML_CONTEXT_BYTES=1024)
target_link_libraries(epub_safety_bounds_tests PRIVATE crosspoint_test_common GTest::gtest_main)
# An Android cross-compile cannot execute the binary on the Windows configure
# host. The release gate pushes it to an emulator with adb; native builds keep
# normal CTest discovery.
if(NOT ANDROID)
  gtest_discover_tests(epub_safety_bounds_tests)
endif()

add_test(
  NAME epub_safety_source_contract
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/verify_source_contract.py
)
add_test(
  NAME epub_safety_source_contract_mutations
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/verify_source_contract_mutations.py
)
set_tests_properties(
  epub_safety_source_contract
  epub_safety_source_contract_mutations
  PROPERTIES TIMEOUT 120
)
