include_directories(.)

add_executable(
  main

  main.cpp
)
target_link_libraries(
  main

  snark
)
target_include_directories(
  main

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

add_executable(
        test

        test.cpp
)
target_link_libraries(
        test

        snark
)
target_include_directories(
        test

        PUBLIC
        ${DEPENDS_DIR}/libsnark
        ${DEPENDS_DIR}/libsnark/depends/libfqfft
        ${DEPENDS_DIR}/libsnark/depends/libff
)

add_executable(
        test-gadget

        test-gadget.cpp
)
target_link_libraries(
        test-gadget

        snark
)
target_include_directories(
        test-gadget

        PUBLIC
        ${DEPENDS_DIR}/libsnark
        ${DEPENDS_DIR}/libsnark/depends/libfqfft
        ${DEPENDS_DIR}/libsnark/depends/libff
)