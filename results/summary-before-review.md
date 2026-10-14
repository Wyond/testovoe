conversion (JSON decode + normalization + write, 10 workers): 15.72s for 1114166 requests, 7339 MB JSON -> 5375 MB normalized

| label | mode | workers | requests | runs | median s | min s | max s | req/s | MB/s | speedup | efficiency |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | naive | 1 | 100000 | 1 | 202.356 | 202.356 | 202.356 | 494 | 2 | 1.00x | 100% |
| baseline | fast | 1 | 100000 | 3 | 0.692 | 0.686 | 0.707 | 144583 | 625 | 1.00x | 100% |
| full | fast | 1 | 1114166 | 3 | 7.351 | 7.310 | 7.384 | 151568 | 731 | 1.00x | 100% |
| full | fast | 2 | 1114166 | 3 | 3.847 | 3.846 | 3.893 | 289639 | 1397 | 1.91x | 96% |
| full | fast | 3 | 1114166 | 3 | 2.921 | 2.864 | 2.961 | 381489 | 1840 | 2.52x | 84% |
| full | fast | 4 | 1114166 | 3 | 2.395 | 2.339 | 2.413 | 465234 | 2244 | 3.07x | 77% |
| full | fast | 6 | 1114166 | 3 | 1.960 | 1.921 | 1.963 | 568403 | 2742 | 3.75x | 63% |
| full | fast | 8 | 1114166 | 3 | 1.637 | 1.634 | 1.677 | 680429 | 3283 | 4.49x | 56% |
| full | fast | 10 | 1114166 | 3 | 1.450 | 1.432 | 1.490 | 768539 | 3708 | 5.07x | 51% |

prefilter vs naive, 1 worker, same 100000 requests: 0.69s vs 202.36s = 293x
