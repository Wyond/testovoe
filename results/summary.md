conversion (JSON decode + normalization + write, 10 workers): 10.81s for 1114166 requests, 7339 MB JSON -> 5375 MB normalized

| label | mode | workers | readers | requests | runs | median s | min s | max s | req/s | MB/s | speedup | efficiency |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| stream-simdjson | fast | 1 | 4 | 1114166 | 6 | 13.696 | 13.560 | 21.564 | 81353 | 392 | 1.00x | 100% |
| stream-simdjson | fast | 2 | 4 | 1114166 | 3 | 7.019 | 6.974 | 8.611 | 158726 | 766 | 1.95x | 98% |
| stream-simdjson | fast | 4 | 4 | 1114166 | 3 | 4.017 | 3.930 | 4.596 | 277396 | 1338 | 3.41x | 85% |
| stream-simdjson | fast | 8 | 4 | 1114166 | 3 | 3.300 | 3.153 | 3.346 | 337577 | 1629 | 4.15x | 52% |
| stream-simdjson | fast | 10 | 4 | 1114166 | 6 | 2.981 | 2.939 | 3.057 | 373772 | 1803 | 4.59x | 46% |
| stream-jx | fast | 1 | 4 | 1114166 | 3 | 18.507 | 18.480 | 18.540 | 60203 | 290 | 1.00x | 100% |
| stream-jx | fast | 10 | 4 | 1114166 | 3 | 4.554 | 4.541 | 4.591 | 244667 | 1180 | 4.06x | 41% |
| stream-simdjson-readers | fast | 10 | 1 | 1114166 | 3 | 3.167 | 3.145 | 3.305 | 351857 | 1698 | - | - |
| stream-simdjson-readers | fast | 10 | 2 | 1114166 | 3 | 3.061 | 2.930 | 3.074 | 364001 | 1756 | - | - |
| stream-simdjson-readers | fast | 10 | 3 | 1114166 | 3 | 3.013 | 2.930 | 3.018 | 369819 | 1784 | - | - |
| stream-simdjson-readers | fast | 10 | 4 | 1114166 | 3 | 2.990 | 2.958 | 3.010 | 372575 | 1797 | - | - |
| baseline | naive | 1 | - | 100000 | 1 | 172.079 | 172.079 | 172.079 | 581 | 3 | 1.00x | 100% |
| baseline | fast | 1 | - | 100000 | 3 | 0.500 | 0.500 | 0.504 | 199833 | 863 | 1.00x | 100% |
| matcher-only | fast | 1 | - | 1114166 | 3 | 4.936 | 4.934 | 4.963 | 225735 | 1089 | 1.00x | 100% |
| matcher-only | fast | 10 | - | 1114166 | 3 | 0.910 | 0.903 | 0.911 | 1224656 | 5908 | 5.43x | 54% |

prefilter vs naive, 1 worker, same 100000 requests: 0.50s vs 172.08s = 344x
