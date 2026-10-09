# Vendored globe libraries (local, no CDN at runtime)
- d3-array 3.2.4 (UMD min)  - required by d3-geo UMD, load FIRST
- d3-geo 3.1.1 (UMD min)    - exposes global `d3`
- topojson-client 3.1.0 (UMD min) - exposes global `topojson`
- world/countries-110m.json from world-atlas 2.0.2 (Natural Earth, public domain); country ids are ISO 3166-1 numeric strings
Fetched from registry.npmjs.org via `npm pack`.
