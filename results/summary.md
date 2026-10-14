conversion (JSON decode + normalization + write, 10 workers): 15.72s for 1114166 requests, 7339 MB JSON -> 5375 MB normalized

| label | mode | workers | requests | runs | median s | min s | max s | req/s | MB/s | speedup | efficiency |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | naive | 1 | 100000 | 1 | 202.742 | 202.742 | 202.742 | 493 | 2 | 1.00x | 100% |
| baseline | fast | 1 | 100000 | 3 | 0.769 | 0.662 | 0.786 | 130002 | 562 | 1.00x | 100% |
| full | fast | 1 | 1114166 | 3 | 7.812 | 7.576 | 7.946 | 142626 | 688 | 1.00x | 100% |
| full | fast | 2 | 1114166 | 3 | 4.204 | 4.150 | 4.343 | 265054 | 1279 | 1.86x | 93% |
| full | fast | 3 | 1114166 | 3 | 3.330 | 3.184 | 3.334 | 334600 | 1614 | 2.35x | 78% |
| full | fast | 4 | 1114166 | 3 | 2.728 | 2.594 | 2.794 | 408467 | 1971 | 2.86x | 72% |
| full | fast | 6 | 1114166 | 3 | 2.168 | 2.130 | 2.178 | 513949 | 2480 | 3.60x | 60% |
| full | fast | 8 | 1114166 | 3 | 1.715 | 1.693 | 1.754 | 649478 | 3133 | 4.55x | 57% |
| full | fast | 10 | 1114166 | 3 | 1.538 | 1.528 | 1.559 | 724553 | 3496 | 5.08x | 51% |

prefilter vs naive, 1 worker, same 100000 requests: 0.77s vs 202.74s = 264x
