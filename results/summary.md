conversion (JSON decode + normalization + write, 10 workers): 10.81s for 1114166 requests, 7339 MB JSON -> 5375 MB normalized

| label | mode | workers | requests | runs | median s | min s | max s | req/s | MB/s | speedup | efficiency |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | naive | 1 | 100000 | 1 | 499.788 | 499.788 | 499.788 | 200 | 1 | 1.00x | 100% |
| baseline | fast | 1 | 100000 | 3 | 1.042 | 0.707 | 1.556 | 95980 | 415 | 1.00x | 100% |
| hybrid+pcre2 | fast | 1 | 1114166 | 3 | 7.006 | 6.796 | 7.455 | 159027 | 767 | 1.00x | 100% |
| hybrid+pcre2 | fast | 2 | 1114166 | 3 | 4.079 | 3.532 | 4.320 | 273160 | 1318 | 1.72x | 86% |
| hybrid+pcre2 | fast | 4 | 1114166 | 3 | 2.139 | 2.003 | 3.209 | 520780 | 2512 | 3.27x | 82% |
| hybrid+pcre2 | fast | 8 | 1114166 | 3 | 1.494 | 1.213 | 1.935 | 745540 | 3597 | 4.69x | 59% |
| hybrid+pcre2 | fast | 10 | 1114166 | 3 | 1.431 | 1.414 | 2.096 | 778660 | 3757 | 4.90x | 49% |
| go | fast | 1 | 1114166 | 3 | 8.849 | 8.305 | 9.999 | 125903 | 607 | 1.00x | 100% |
| go | fast | 10 | 1114166 | 3 | 1.836 | 1.731 | 2.224 | 606998 | 2928 | 4.82x | 48% |

prefilter vs naive, 1 worker, same 100000 requests: 1.04s vs 499.79s = 480x
