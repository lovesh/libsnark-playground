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

# Utility rule file for NightlyBuild.

# Include the progress variables for this target.
include depends/libsnark/libsnark/CMakeFiles/NightlyBuild.dir/progress.make

depends/libsnark/libsnark/CMakeFiles/NightlyBuild:
	cd /home/lovesh/dev/libsnark-tutorial/cmake-build-debug/depends/libsnark/libsnark && /home/lovesh/Downloads/clion-182.4129.15/bin/cmake/linux/bin/ctest -D NightlyBuild

NightlyBuild: depends/libsnark/libsnark/CMakeFiles/NightlyBuild
NightlyBuild: depends/libsnark/libsnark/CMakeFiles/NightlyBuild.dir/build.make

.PHONY : NightlyBuild

# Rule to build all files generated by this target.
depends/libsnark/libsnark/CMakeFiles/NightlyBuild.dir/build: NightlyBuild

.PHONY : depends/libsnark/libsnark/CMakeFiles/NightlyBuild.dir/build

depends/libsnark/libsnark/CMakeFiles/NightlyBuild.dir/clean:
	cd /home/lovesh/dev/libsnark-tutorial/cmake-build-debug/depends/libsnark/libsnark && $(CMAKE_COMMAND) -P CMakeFiles/NightlyBuild.dir/cmake_clean.cmake
.PHONY : depends/libsnark/libsnark/CMakeFiles/NightlyBuild.dir/clean

depends/libsnark/libsnark/CMakeFiles/NightlyBuild.dir/depend:
	cd /home/lovesh/dev/libsnark-tutorial/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/lovesh/dev/libsnark-tutorial /home/lovesh/dev/libsnark-tutorial/depends/libsnark/libsnark /home/lovesh/dev/libsnark-tutorial/cmake-build-debug /home/lovesh/dev/libsnark-tutorial/cmake-build-debug/depends/libsnark/libsnark /home/lovesh/dev/libsnark-tutorial/cmake-build-debug/depends/libsnark/libsnark/CMakeFiles/NightlyBuild.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : depends/libsnark/libsnark/CMakeFiles/NightlyBuild.dir/depend

