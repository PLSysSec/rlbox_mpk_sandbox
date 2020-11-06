# RLBOX MPK Sandbox Integration

Integration with RLBox sandboxing API to leverage the sandboxing provided by Intel MPK (Memory Protection Keys).

**Note:**  This repo is only meant to simulate the performance cost of MPK transitions.

For details about the RLBox sandboxing APIs, see [here](https://github.com/PLSysSec/rlbox_api_cpp17).

## Building/Running the tests

You can build and run the tests using cmake with the following commands.

```bash
cmake -S . -B ./build
cmake --build ./build --target all
cmake --build ./build --target test
```

On Arch Linux you'll need to install [ncurses5-compat-libs](https://aur.archlinux.org/packages/ncurses5-compat-libs/).

## Using this library

First, build the rlbox_lucet_sandbox repo with

```bash
cmake -S . -B ./build
cmake --build ./build --target all
```
