# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.12

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /home/lovesh/Downloads/clion-182.4129.15/bin/cmake/linux/bin/cmake

# The command to remove a file.
RM = /home/lovesh/Downloads/clion-182.4129.15/bin/cmake/linux/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/lovesh/dev/libsnark-tutorial

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/lovesh/dev/libsnark-tutorial/cmake-build-debug

# Include any dependencies generated for this target.
include src/CMakeFiles/test-gadget.dir/depend.make

# Include the progress variables for this target.
include src/CMakeFiles/test-gadget.dir/progress.make

# Include the compile flags for this target's objects.
include src/CMakeFiles/test-gadget.dir/flags.make

src/CMakeFiles/test-gadget.dir/test-gadget.cpp.o: src/CMakeFiles/test-gadget.dir/flags.make
src/CMakeFiles/test-gadget.dir/test-gadget.cpp.o: ../src/test-gadget.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/lovesh/dev/libsnark-tutorial/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object src/CMakeFiles/test-gadget.dir/test-gadget.cpp.o"
	cd /home/lovesh/dev/libsnark-tutorial/cmake-build-debug/src && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/test-gadget.dir/test-gadget.cpp.o -c /home/lovesh/dev/libsnark-tutorial/src/test-gadget.cpp

src/CMakeFiles/test-gadget.dir/test-gadget.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/test-gadget.dir/test-gadget.cpp.i"
	cd /home/lovesh/dev/libsnark-tutorial/cmake-build-debug/src && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/lovesh/dev/libsnark-tutorial/src/test-gadget.cpp > CMakeFiles/test-gadget.dir/test-gadget.cpp.i

src/CMakeFiles/test-gadget.dir/test-gadget.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/test-gadget.dir/test-gadget.cpp.s"
	cd /home/lovesh/dev/libsnark-tutorial/cmake-build-debug/src && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/lovesh/dev/libsnark-tutorial/src/test-gadget.cpp -o CMakeFiles/test-gadget.dir/test-gadget.cpp.s

# Object files for target test-gadget
test__gadget_OBJECTS = \
"CMakeFiles/test-gadget.dir/test-gadget.cpp.o"

# External object files for target test-gadget
test__gadget_EXTERNAL_OBJECTS =

src/test-gadget: src/CMakeFiles/test-gadget.dir/test-gadget.cpp.o
src/test-gadget: src/CMakeFiles/test-gadget.dir/build.make
src/test-gadget: depends/libsnark/libsnark/libsnarkd.a
src/test-gadget: depends/libsnark/depends/libff/libff/libffd.a
src/test-gadget: /usr/lib/x86_64-linux-gnu/libgmp.so
src/test-gadget: /usr/lib/x86_64-linux-gnu/libgmp.so
src/test-gadget: /usr/lib/x86_64-linux-gnu/libgmpxx.so
src/test-gadget: depends/libsnark/depends/libzmd.a
src/test-gadget: src/CMakeFiles/test-gadget.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/lovesh/dev/libsnark-tutorial/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable test-gadget"
	cd /home/lovesh/dev/libsnark-tutorial/cmake-build-debug/src && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test-gadget.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/CMakeFiles/test-gadget.dir/build: src/test-gadget

.PHONY : src/CMakeFiles/test-gadget.dir/build

src/CMakeFiles/test-gadget.dir/clean:
	cd /home/lovesh/dev/libsnark-tutorial/cmake-build-debug/src && $(CMAKE_COMMAND) -P CMakeFiles/test-gadget.dir/cmake_clean.cmake
.PHONY : src/CMakeFiles/test-gadget.dir/clean

src/CMakeFiles/test-gadget.dir/depend:
	cd /home/lovesh/dev/libsnark-tutorial/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/lovesh/dev/libsnark-tutorial /home/lovesh/dev/libsnark-tutorial/src /home/lovesh/dev/libsnark-tutorial/cmake-build-debug /home/lovesh/dev/libsnark-tutorial/cmake-build-debug/src /home/lovesh/dev/libsnark-tutorial/cmake-build-debug/src/CMakeFiles/test-gadget.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/CMakeFiles/test-gadget.dir/depend

