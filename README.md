# uMMAP-IO: User-level Memory-mapped I/O for HPC

## Introduction
The integration of local storage technologies alongside traditional parallel file systems on HPC clusters, is expected to rise the programming complexity on scientific applications aiming to take advantage of the increased-level of heterogeneity.

The User-level Memory-mapped I/O (**uMMAP-IO**) is a library that simplifies data management on multi-tier storage subsystems. Compared to the memory-mapped I/O mechanism of the OS, our approach features per-allocation configurable settings (e.g., segment size) and transparently enables access to a diverse range of memory and storage technologies, such as the burst buffer I/O accelerators.

See the following paper for further technical information and experimental results:

```
"uMMAP-IO: User-level Memory-mapped I/O for HPC"
S. Rivas-Gomez, A. Fanfarillo, S. Valat, C. Laferriere, P. Couvee, S. Narasimhamurthy, and S. Markidis.
26th IEEE International Conference on High-Performance Computing, Data, and Analytics (HiPC 2019)
```


## How to compile and use the library
In order to compile **uMMAP-IO**, the `src` folder contains the source code and all the necessary elements. Type the following to compile both the library and a simple example application:

```
git clone https://github.com/sergiorg-kth/ummap-io.git
cd ummap-io/src/
make rebuild
```

If the compilation is successful, you will now observe inside `ummap-io/` a new `build/` folder that contains the following structure:

- `ummap-io/build/bin`: The executable of the source code example is located here.
- `ummap-io/build/lib`: Static library for **uMMAP-IO**, named `libummapio.a`. It can be utilized to compile with your code by including `-lummapio`. Optionally, some compilers might require `-pthread -lrt` as well.
- `ummap-io/build/inc`: A header file, named `ummap.h`, is provided with the definition of the API.
- `ummap-io/build/...`: Other temporary folders might be created (ignore).

The source code example can be executed directly. By default, a 1GB file will be created. You can observe whether the output was correct or not by typing the following:

```
> hexdump example.data
0000000 1515 1515 1515 1515 1515 1515 1515 1515
*
40000000
```

That is all!


## Simplified API

A malloc-like interface is also available to use on the following repository:

https://github.com/sergiorg-kth/umalloc

This wrapper utilizes **uMMAP-IO** with certain default settings, while hiding the complexity to applications.


## Known Bugs / Limitations
The implementation of **uMMAP-IO** contains the following known bugs and limitations:
* **Unable to map, unmap, and map again.** See [Issue #1](https://github.com/sergiorg-kth/ummap-io/issues/1) for a fix.
* **Integration as part of another library is not supported.** See [Issue #1](https://github.com/sergiorg-kth/ummap-io/issues/1) for a fix.
* **Multi-threading is not supported.** A solution is not available yet, but we plan to work on it.
* **I/O drivers are not supported.** A solution is not available yet, but we plan to work on it.

## Disclaimer
Even though the current `alpha` release of **uMMAP-IO** is relatively stable, we kindly ask you to report any issues that you might encounter on the [Issues](https://github.com/sergiorg-kth/ummap-io/issues) tab.
