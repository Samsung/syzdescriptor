# syzdescriptor: syzkaller syscall and structure description generator for Linux
`syzdescriptor` generates syzkaller descriptions by analyzing the code of a compiled
kernel. It uses [FTDB](https://github.com/Samsung/CAS) for means of
easy static analysis.  

It allows the user to generate accurate and fuzzing-ready syzkaller descriptions
for a given kernel build.

# Building
Requirements:
  * Python 3.12
  * [`libcas`](https://github.com/Samsung/CAS)
  * [SEAL](https://github.com/Samsung/seal) (if you want fuzzing ready configs, SEAL has to generate mapping between kernel functions and filesystem nodes)

All Python dependencies should be satisifed by installing `syzdescriptor` with pip.

## Installation
```sh
pip install https://github.com/Samsung/syzdescriptor
```

# Example usage
Generate configs, filtered by permissions from SEAL. Passing `--software-version` and `--model` will generate `info.json` summary file
```sh
$ syzdescriptor vmlinux_db.img --foka foka_v2.json --filter-permissions --arch arm64 -o full_configs/ --software-version 1234 --model PIXEL2
```

Generate configs without paths to nodes, if you don't have SEAL at the time of generation
```sh
$ syzdescriptor vmlinux_db.img --arch arm64 -o stub_configs/
```

Replace stub comments with actual `open()` syscalls (does in place replacement so `-o` argument must point to a working directory containing previously generated stubs)
```sh
$ syzdescriptor vmlinux_db.img --replace -o stub_configs/ --filter-permissions --foka foka_v2.json
```

# Contact
  * Main maintainer: [michal.lach@samsung.com](mailto:michal.lach@samsung.com)

# Authors
  * Michał Lach (`<michal.lach@samsung.com>`)

# Credits
  * Mateusz Mańko (Author of original, clang-based `syzdescriptor`)

# License
`syzdescriptor` is an Open Source project released under the term of MIT License
