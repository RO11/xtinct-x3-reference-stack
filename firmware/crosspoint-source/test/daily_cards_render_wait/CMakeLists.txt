add_test(
  NAME daily_cards_render_wait_source_contract
  COMMAND ${Python3_EXECUTABLE} -B ${CMAKE_CURRENT_SOURCE_DIR}/verify_source_contract.py
)
