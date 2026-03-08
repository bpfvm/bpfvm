if(NOT DEFINED BPFVM)
    message(FATAL_ERROR "BPFVM is required")
endif()

if(NOT DEFINED PROGRAM)
    message(FATAL_ERROR "PROGRAM is required")
endif()

if(NOT DEFINED EXPECTED_EXIT)
    message(FATAL_ERROR "EXPECTED_EXIT is required")
endif()

if(NOT DEFINED WORKDIR)
    set(WORKDIR "${CMAKE_CURRENT_LIST_DIR}/..")
endif()

execute_process(
    COMMAND "${BPFVM}" "${PROGRAM}"
    WORKING_DIRECTORY "${WORKDIR}"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE stdout
    ERROR_VARIABLE stderr
)

if(NOT result EQUAL EXPECTED_EXIT)
    message("stdout:\n${stdout}")
    message("stderr:\n${stderr}")
    message(FATAL_ERROR
        "Program ${PROGRAM} exited with ${result}, expected ${EXPECTED_EXIT}"
    )
endif()
