conversion (JSON decode + normalization + write, 10 workers): 10.81s for 1114166 requests, 7339 MB JSON -> 5375 MB normalized

| label | mode | workers | requests | runs | median s | min s | max s | req/s | MB/s | speedup | efficiency |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| stream-simdjson | fast | 1 | 1114166 | 1 | 17.965 | 17.965 | 17.965 | 62019 | 299 | 1.00x | 100% |
| stream-simdjson | fast | 10 | 1114166 | 2 | 6.503 | 5.066 | 6.503 | 171325 | 827 | 2.76x | 28% |
| stream-jx | fast | 10 | 1114166 | 1 | 8.632 | 8.632 | 8.632 | 129068 | 623 | - | - |
| baseline | naive | 1 | 10000 | 1 | 28.032 | 28.032 | 28.032 | 357 | 2 | 1.00x | 100% |
| baseline | fast | 1 | 10000 | 1 | 0.098 | 0.098 | 0.098 | 101856 | 443 | 1.00x | 100% |
| matcher-only | fast | 1 | 1114166 | 1 | 8.912 | 8.912 | 8.912 | 125025 | 603 | 1.00x | 100% |
| matcher-only | fast | 10 | 1114166 | 1 | 2.982 | 2.982 | 2.982 | 373589 | 1802 | 2.99x | 30% |

prefilter vs naive, 1 worker, same 10000 requests: 0.10s vs 28.03s = 286x
