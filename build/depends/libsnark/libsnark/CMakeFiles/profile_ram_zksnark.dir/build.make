# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.10

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
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/lovesh/dev/libsnark-tutorial

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/lovesh/dev/libsnark-tutorial/build

# Include any dependencies generated for this target.
include depends/libsnark/libsnark/CMakeFiles/profile_ram_zksnark.dir/depend.make

# Include the progress variables for this target.
include depends/libsnark/libsnark/CMakeFiles/profile_ram_zksnark.dir/progress.make

# Include the compile flags for this target's objects.
include depends/libsnark/libsnark/CMakeFiles/profile_ram_zksnark.dir/flags.make

depends/libsnark/libsnark/CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.o: depends/libsnark/libsnark/CMakeFiles/profile_ram_zksnark.dir/flags.make
depends/libsnark/libsnark/CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.o: ../depends/libsnark/libsnark/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/lovesh/dev/libsnark-tutorial/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object depends/libsnark/libsnark/CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.o"
	cd /home/lovesh/dev/libsnark-tutorial/build/depends/libsnark/libsnark && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.o -c /home/lovesh/dev/libsnark-tutorial/depends/libsnark/libsnark/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp

depends/libsnark/libsnark/CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.i"
	cd /home/lovesh/dev/libsnark-tutorial/build/depends/libsnark/libsnark && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/lovesh/dev/libsnark-tutorial/depends/libsnark/libsnark/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp > CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.i

depends/libsnark/libsnark/CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.s"
	cd /home/lovesh/dev/libsnark-tutorial/build/depends/libsnark/libsnark && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/lovesh/dev/libsnark-tutorial/depends/libsnark/libsnark/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp -o CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.s

depends/libsnark/libsnark/CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.o.requires:

.PHONY : depends/libsnark/libsnark/CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.o.requires

depends/libsnark/libsnark/CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.o.provides: depends/libsnark/libsnark/CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.o.requires
	$(MAKE) -f depends/libsnark/libsnark/CMakeFiles/profile_ram_zksnark.dir/build.make depends/libsnark/libsnark/CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.o.provides.build
.PHONY : depends/libsnark/libsnark/CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.o.provides

depends/libsnark/libsnark/CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.o.provides.build: depends/libsnark/libsnark/CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.o


# Object files for target profile_ram_zksnark
profile_ram_zksnark_OBJECTS = \
"CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.o"

# External object files for target profile_ram_zksnark
profile_ram_zksnark_EXTERNAL_OBJECTS =

depends/libsnark/libsnark/profile_ram_zksnark: depends/libsnark/libsnark/CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.o
depends/libsnark/libsnark/profile_ram_zksnark: depends/libsnark/libsnark/CMakeFiles/profile_ram_zksnark.dir/build.make
depends/libsnark/libsnark/profile_ram_zksnark: depends/libsnark/libsnark/libsnark.a
depends/libsnark/libsnark/profile_ram_zksnark: /usr/lib/x86_64-linux-gnu/libboost_program_options.so
depends/libsnark/libsnark/profile_ram_zksnark: depends/libsnark/depends/libff/libff/libff.a
depends/libsnark/libsnark/profile_ram_zksnark: /usr/lib/x86_64-linux-gnu/libgmp.so
depends/libsnark/libsnark/profile_ram_zksnark: /usr/lib/x86_64-linux-gnu/libgmp.so
depends/libsnark/libsnark/profile_ram_zksnark: /usr/lib/x86_64-linux-gnu/libgmpxx.so
depends/libsnark/libsnark/profile_ram_zksnark: depends/libsnark/depends/libzm.a
depends/libsnark/libsnark/profile_ram_zksnark: depends/libsnark/libsnark/CMakeFiles/profile_ram_zksnark.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/lovesh/dev/libsnark-tutorial/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable profile_ram_zksnark"
	cd /home/lovesh/dev/libsnark-tutorial/build/depends/libsnark/libsnark && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/profile_ram_zksnark.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
depends/libsnark/libsnark/CMakeFiles/profile_ram_zksnark.dir/build: depends/libsnark/libsnark/profile_ram_zksnark

.PHONY : depends/libsnark/libsnark/CMakeFiles/profile_ram_zksnark.dir/build

depends/libsnark/libsnark/CMakeFiles/profile_ram_zksnark.dir/requires: depends/libsnark/libsnark/CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.o.requires

.PHONY : depends/libsnark/libsnark/CMakeFiles/profile_ram_zksnark.dir/requires

depends/libsnark/libsnark/CMakeFiles/profile_ram_zksnark.dir/clean:
	cd /home/lovesh/dev/libsnark-tutorial/build/depends/libsnark/libsnark && $(CMAKE_COMMAND) -P CMakeFiles/profile_ram_zksnark.dir/cmake_clean.cmake
.PHONY : depends/libsnark/libsnark/CMakeFiles/profile_ram_zksnark.dir/clean

depends/libsnark/libsnark/CMakeFiles/profile_ram_zksnark.dir/depend:
	cd /home/lovesh/dev/libsnark-tutorial/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/lovesh/dev/libsnark-tutorial /home/lovesh/dev/libsnark-tutorial/depends/libsnark/libsnark /home/lovesh/dev/libsnark-tutorial/build /home/lovesh/dev/libsnark-tutorial/build/depends/libsnark/libsnark /home/lovesh/dev/libsnark-tutorial/build/depends/libsnark/libsnark/CMakeFiles/profile_ram_zksnark.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : depends/libsnark/libsnark/CMakeFiles/profile_ram_zksnark.dir/depend

