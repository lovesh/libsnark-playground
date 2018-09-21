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
)

add_executable(
        factorisation

        factorisation.cpp
)
target_link_libraries(
        factorisation

        snark
)
target_include_directories(
        factorisation

        PUBLIC
        ${DEPENDS_DIR}/libsnark
        ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

add_executable(
        sha256

        sha256.cpp
)
target_link_libraries(
        sha256

        snark
)
target_include_directories(
        sha256

        PUBLIC
        ${DEPENDS_DIR}/libsnark
        ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

#add_subdirectory(common)

add_executable(
        mimc

        mimc.cpp
)
target_link_libraries(
        mimc

        snark
)
target_include_directories(
        mimc

        PUBLIC
        ${DEPENDS_DIR}/libsnark
        ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

add_executable(
        longsightf-gadget

        longsightf-gadget.cpp
)
target_link_libraries(
        longsightf-gadget

        snark
)
target_include_directories(
        longsightf-gadget

        PUBLIC
        ${DEPENDS_DIR}/libsnark
        ${DEPENDS_DIR}/libsnark/depends/libfqfft
)
