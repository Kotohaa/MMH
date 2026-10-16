#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "AESModes::aes_modes_static" for configuration "Release"
set_property(TARGET AESModes::aes_modes_static APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(AESModes::aes_modes_static PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libaes_modes_static.a"
  )

list(APPEND _cmake_import_check_targets AESModes::aes_modes_static )
list(APPEND _cmake_import_check_files_for_AESModes::aes_modes_static "${_IMPORT_PREFIX}/lib/libaes_modes_static.a" )

# Import target "AESModes::aes_modes_shared" for configuration "Release"
set_property(TARGET AESModes::aes_modes_shared APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(AESModes::aes_modes_shared PROPERTIES
  IMPORTED_IMPLIB_RELEASE "${_IMPORT_PREFIX}/lib/libaes_modes.dll.a"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/bin/libaes_modes.dll"
  )

list(APPEND _cmake_import_check_targets AESModes::aes_modes_shared )
list(APPEND _cmake_import_check_files_for_AESModes::aes_modes_shared "${_IMPORT_PREFIX}/lib/libaes_modes.dll.a" "${_IMPORT_PREFIX}/bin/libaes_modes.dll" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
