conversion (JSON decode + normalization + write, 10 workers): 10.81s for 1114166 requests, 7339 MB JSON -> 5375 MB normalized

| label | mode | workers | requests | runs | median s | min s | max s | req/s | MB/s | speedup | efficiency |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| stream-simdjson | fast | 1 | 1114166 | 6 | 16.753 | 14.513 | 17.190 | 66504 | 321 | 1.00x | 100% |
| stream-simdjson | fast | 2 | 1114166 | 3 | 9.075 | 8.636 | 9.363 | 122777 | 592 | 1.85x | 92% |
| stream-simdjson | fast | 4 | 1114166 | 3 | 5.157 | 4.828 | 5.639 | 216069 | 1042 | 3.25x | 81% |
| stream-simdjson | fast | 8 | 1114166 | 3 | 4.289 | 4.238 | 4.307 | 259796 | 1253 | 3.91x | 49% |
| stream-simdjson | fast | 10 | 1114166 | 6 | 4.096 | 3.577 | 4.240 | 272025 | 1312 | 4.09x | 41% |
| stream-jx | fast | 1 | 1114166 | 3 | 19.604 | 19.576 | 20.788 | 56835 | 274 | 1.00x | 100% |
| stream-jx | fast | 10 | 1114166 | 3 | 5.108 | 5.010 | 5.153 | 218116 | 1052 | 3.84x | 38% |
| baseline | naive | 1 | 100000 | 1 | 172.984 | 172.984 | 172.984 | 578 | 2 | 1.00x | 100% |
| baseline | fast | 1 | 100000 | 3 | 0.528 | 0.498 | 2.082 | 189240 | 818 | 1.00x | 100% |
| matcher-only | fast | 1 | 1114166 | 3 | 4.935 | 4.898 | 5.236 | 225772 | 1089 | 1.00x | 100% |
| matcher-only | fast | 10 | 1114166 | 3 | 0.946 | 0.894 | 0.976 | 1177771 | 5682 | 5.22x | 52% |

prefilter vs naive, 1 worker, same 100000 requests: 0.53s vs 172.98s = 327x
