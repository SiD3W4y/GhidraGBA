# GhidraGBA: GBA ROM loader for ghidra
This project is a (very) simple loader for GBA ROMS. It only maps memory and defines the entrypoint.

## Installation
- Use a release zip if it exists.

or

- Build using gradle: ```$ gradle```
- Copy the generated zip in **dist/** to **Extensions/Ghidra** in the ghidra installation folder.
- Open ghidra and go to **File -> Install Extensions...** and check the plugin for installation
