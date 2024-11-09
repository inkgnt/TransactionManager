# Additional clean files
cmake_minimum_required(VERSION 3.16)

if("${CONFIG}" STREQUAL "" OR "${CONFIG}" STREQUAL "Debug")
  file(REMOVE_RECURSE
  "221_329_Dorohov_Exam_autogen"
  "CMakeFiles\\221_329_Dorohov_Exam_autogen.dir\\AutogenUsed.txt"
  "CMakeFiles\\221_329_Dorohov_Exam_autogen.dir\\ParseCache.txt"
  )
endif()
