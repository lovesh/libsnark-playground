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
include depends/libsnark/libsnark/CMakeFiles/profile_routing_gadgets.dir/depend.make

# Include the progress variables for this target.
include depends/libsnark/libsnark/CMakeFiles/profile_routing_gadgets.dir/progress.make

# Include the compile flags for this target's objects.
include depends/libsnark/libsnark/CMakeFiles/profile_routing_gadgets.dir/flags.make

depends/libsnark/libsnark/CMakeFiles/profile_routing_gadgets.dir/gadgetlib1/gadgets/routing/profiling/profile_routing_gadgets.cpp.o: depends/libsnark/libsnark/CMakeFiles/profile_routing_gadgets.dir/flags.make
depends/libsnark/libsnark/CMakeFiles/profile_routing_gadgets.dir/gadgetlib1/gadgets/routing/profiling/profile_routing_gadgets.cpp.o: ../depends/libsnark/libsnark/gadgetlib1/gadgets/routing/profiling/profile_routing_gadgets.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/lovesh/dev/libsnark-tutorial/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object depends/libsnark/libsnark/CMakeFiles/profile_routing_gadgets.dir/gadgetlib1/gadgets/routing/profiling/profile_routing_gadgets.cpp.o"
	cd /home/lovesh/dev/libsnark-tutorial/cmake-build-debug/depends/libsnark/libsnark && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/profile_routing_gadgets.dir/gadgetlib1/gadgets/routing/profiling/profile_routing_gadgets.cpp.o -c /home/lovesh/dev/libsnark-tutorial/depends/libsnark/libsnark/gadgetlib1/gadgets/routing/profiling/profile_routing_gadgets.cpp

depends/libsnark/libsnark/CMakeFiles/profile_routing_gadgets.dir/gadgetlib1/gadgets/routing/profiling/profile_routing_gadgets.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/profile_routing_gadgets.dir/gadgetlib1/gadgets/routing/profiling/profile_routing_gadgets.cpp.i"
	cd /home/lovesh/dev/libsnark-tutorial/cmake-build-debug/depends/libsnark/libsnark && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/lovesh/dev/libsnark-tutorial/depends/libsnark/libsnark/gadgetlib1/gadgets/routing/profiling/profile_routing_gadgets.cpp > CMakeFiles/profile_routing_gadgets.dir/gadgetlib1/gadgets/routing/profiling/profile_routing_gadgets.cpp.i

depends/libsnark/libsnark/CMakeFiles/profile_routing_gadgets.dir/gadgetlib1/gadgets/routing/profiling/profile_routing_gadgets.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/profile_routing_gadgets.dir/gadgetlib1/gadgets/routing/profiling/profile_routing_gadgets.cpp.s"
	cd /home/lovesh/dev/libsnark-tutorial/cmake-build-debug/depends/libsnark/libsnark && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/lovesh/dev/libsnark-tutorial/depends/libsnark/libsnark/gadgetlib1/gadgets/routing/profiling/profile_routing_gadgets.cpp -o CMakeFiles/profile_routing_gadgets.dir/gadgetlib1/gadgets/routing/profiling/profile_routing_gadgets.cpp.s

# Object files for target profile_routing_gadgets
profile_routing_gadgets_OBJECTS = \
"CMakeFiles/profile_routing_gadgets.dir/gadgetlib1/gadgets/routing/profiling/profile_routing_gadgets.cpp.o"

# External object files for target profile_routing_gadgets
profile_routing_gadgets_EXTERNAL_OBJECTS =

depends/libsnark/libsnark/profile_routing_gadgets: depends/libsnark/libsnark/CMakeFiles/profile_routing_gadgets.dir/gadgetlib1/gadgets/routing/profiling/profile_routing_gadgets.cpp.o
depends/libsnark/libsnark/profile_routing_gadgets: depends/libsnark/libsnark/CMakeFiles/profile_routing_gadgets.dir/build.make
depends/libsnark/libsnark/profile_routing_gadgets: depends/libsnark/libsnark/libsnarkd.a
depends/libsnark/libsnark/profile_routing_gadgets: depends/libsnark/depends/libff/libff/libffd.a
depends/libsnark/libsnark/profile_routing_gadgets: /usr/lib/x86_64-linux-gnu/libgmp.so
depends/libsnark/libsnark/profile_routing_gadgets: /usr/lib/x86_64-linux-gnu/libgmp.so
depends/libsnark/libsnark/profile_routing_gadgets: /usr/lib/x86_64-linux-gnu/libgmpxx.so
depends/libsnark/libsnark/profile_routing_gadgets: depends/libsnark/depends/libzmd.a
depends/libsnark/libsnark/profile_routing_gadgets: depends/libsnark/libsnark/CMakeFiles/profile_routing_gadgets.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/lovesh/dev/libsnark-tutorial/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable profile_routing_gadgets"
	cd /home/lovesh/dev/libsnark-tutorial/cmake-build-debug/depends/libsnark/libsnark && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/profile_routing_gadgets.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
depends/libsnark/libsnark/CMakeFiles/profile_routing_gadgets.dir/build: depends/libsnark/libsnark/profile_routing_gadgets

.PHONY : depends/libsnark/libsnark/CMakeFiles/profile_routing_gadgets.dir/build

depends/libsnark/libsnark/CMakeFiles/profile_routing_gadgets.dir/clean:
	cd /home/lovesh/dev/libsnark-tutorial/cmake-build-debug/depends/libsnark/libsnark && $(CMAKE_COMMAND) -P CMakeFiles/profile_routing_gadgets.dir/cmake_clean.cmake
.PHONY : depends/libsnark/libsnark/CMakeFiles/profile_routing_gadgets.dir/clean

depends/libsnark/libsnark/CMakeFiles/profile_routing_gadgets.dir/depend:
	cd /home/lovesh/dev/libsnark-tutorial/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/lovesh/dev/libsnark-tutorial /home/lovesh/dev/libsnark-tutorial/depends/libsnark/libsnark /home/lovesh/dev/libsnark-tutorial/cmake-build-debug /home/lovesh/dev/libsnark-tutorial/cmake-build-debug/depends/libsnark/libsnark /home/lovesh/dev/libsnark-tutorial/cmake-build-debug/depends/libsnark/libsnark/CMakeFiles/profile_routing_gadgets.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : depends/libsnark/libsnark/CMakeFiles/profile_routing_gadgets.dir/depend

