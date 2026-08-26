cmake_minimum_required(VERSION 3.16)
project(crosspoint_reader_tests C CXX)

# Source-contract tests are release gates. Missing Python must fail configure;
# silently omitting those tests would turn memory-safety regressions into a pass.
find_package(Python3 REQUIRED COMPONENTS Interpreter)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

include(FetchContent)

FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG v1.17.0
)

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

set(REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/..")

add_library(crosspoint_test_common INTERFACE)
target_include_directories(crosspoint_test_common INTERFACE
  ${REPO_ROOT}
  ${REPO_ROOT}/lib
)
target_compile_options(crosspoint_test_common INTERFACE
  -Wall
  -Wextra
  -pedantic
)

enable_testing()
include(GoogleTest)

add_test(
  NAME x3_resource_budget_source_contract
  COMMAND ${Python3_EXECUTABLE} -B ${REPO_ROOT}/scripts/check_x3_resource_budgets.py
)
add_test(
  NAME x3_resource_budget_checker_self_test
  COMMAND ${Python3_EXECUTABLE} -B ${REPO_ROOT}/scripts/check_x3_resource_budgets.py --self-test
)
add_test(
  NAME xtinct_content_recovery_source_contract
  COMMAND ${Python3_EXECUTABLE} -B ${REPO_ROOT}/test/xtinct_content_recovery/verify_source_contract.py
)

add_subdirectory(streaming_json_parser)
add_subdirectory(release_json_parser)
add_subdirectory(differential_rounding)
add_subdirectory(hyphenation_eval)
add_subdirectory(utf8_compose)
add_subdirectory(opds_filename)
add_subdirectory(minibidi_arabic)
add_subdirectory(combining_marks)
add_subdirectory(xtinct_date_format)
add_subdirectory(local_time_math)
add_subdirectory(xtinct_report_cache_naming)
add_subdirectory(bounded_utf8_wrap)
add_subdirectory(bounded_response_buffer)
add_subdirectory(xtinct_sync_contract)
add_subdirectory(button_menu_layout)
add_subdirectory(inbox_newest_selection)
add_subdirectory(xtinct_wake_schedule)
add_subdirectory(xtinct_wake_runtime_policy)
add_subdirectory(xtinct_feed_credential_policy)
add_subdirectory(pocket_sync_contract)
add_subdirectory(xtinct_boot_recovery)
add_subdirectory(file_transfer_safety)
add_subdirectory(persistable_store_policy)
add_subdirectory(xtinct_atomic_file)
add_subdirectory(epub_safety_bounds)
add_subdirectory(daily_cards_freshness)
add_subdirectory(daily_cards_render_wait)
add_subdirectory(inbox_digest)
add_subdirectory(reader_open_policy)
add_subdirectory(sleep_screen_refresh)
