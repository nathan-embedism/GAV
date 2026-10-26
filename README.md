# GAV

Password protected. Served from `index.html` via GitHub Pages.

## Editing

The readable source lives in `src/`, which is git-ignored and must never be committed.

```sh
GAV_PASSWORD=... node tools/crypt.mjs unpack   # index.html -> src/
python3 -m http.server -d src 8000             # play locally at http://localhost:8000
GAV_PASSWORD=... node tools/crypt.mjs build    # src/ -> encrypted index.html
```

Controls on a keyboard: arrows, Z = A, X = B, Enter = Start, Shift = Select.
