# simple-port-forwarder Repository Guide

Welcome to the `simple-port-forwarder` repository — a small TCP port forwarder built on the p101 libraries. This guide will help you set up, build, and run the program.

## **Table of Contents**

1. [Cloning the Repository](#cloning-the-repository)
2. [Prerequisites](#prerequisites)
3. [Configuring the Build](#configuring-the-build)
4. [Building](#building)
5. [Testing](#testing)
6. [Running](#running)
7. [Adding or Removing Files](#adding-or-removing-files)

## **Cloning the Repository**

Clone the repository using the following command:

```bash
git clone https://github.com/programming101dev/simple-port-forwarder.git
```

Navigate to the cloned directory:

```bash
cd simple-port-forwarder
```

Ensure the scripts are executable:

```bash
chmod +x *.sh
```

## **Prerequisites**

The p101 libraries must be installed first (clone the [scripts](https://github.com/programming101dev/scripts) repository and run its `setup.sh`). Then, to ensure you have all of the required tools installed, run:

```bash
./check-env.sh
```

If you are missing tools follow these [instructions](https://docs.google.com/document/d/1ZPqlPD1mie5iwJ2XAcNGz7WeA86dTLerFXs9sAuwCco/edit?usp=drive_link). If something still looks wrong, `./doctor.sh` reports what actually works on this machine for this project.

## **Configuring the Build**

Tell CMake which compiler you want to use:

```bash
./change-compiler.sh -c <compiler>
```

To see the list of possible compilers:

```bash
cat supported_c_compilers.txt
```

Run it again any time to switch compilers; each compiler configures into its own build directory (e.g. `build-clang`, `build-gcc-15`).

## **Building**

To build the program run:

```bash
./build.sh
```

This compiles through the strict analysis pipeline: the clang-format check, clang-tidy, cppcheck, the Clang static analyzer, and hundreds of warnings under `-Werror`. `./build.sh -f` applies the formatter and tidy fixes in place.

## **Testing**

`./check.sh` runs the pre-submit gate: the format check, the strict build, the tests, and a short fuzz smoke run, with a single PASS/FAIL at the end. This program does not have `test/` or `fuzz/` trees yet, so those stages report that and move on.

## **Running**

The binary lands in the configured build directory (e.g. `build-clang/main`). Run it with no arguments to see the usage message listing the required listening/forwarding addresses, ports, and backlog.

## **Adding or Removing Files**

The `CMakeLists.txt` is fixed and shared across every repository — do not edit it. When you add or remove a source or header, edit the lists in `config.cmake` (`main_SOURCES`, `main_HEADERS`, and `main_LINK_LIBRARIES`), then re-configure and build:

```bash
./change-compiler.sh -c <compiler>
./build.sh
```
