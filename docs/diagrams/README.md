# Diagrams

Source files are `.excalidraw` scenes. Open them at
[excalidraw.com](https://excalidraw.com) — *File → Open* — or with the
Excalidraw extension in VS Code, which edits them in place.

| File | Shows |
|---|---|
| `waf-ops-architecture.excalidraw` | Request path for both environments, the rule ladder with per-environment modes, the blocked direct-origin path, and log delivery |

## Exporting for the README

In Excalidraw: *File → Export image*, then

- **SVG**, background on, 1× — best for a README; stays sharp and the file is small.
- **PNG**, background on, 2× — if you need a raster for slides.

Save the export next to the source as `waf-ops-architecture.svg` and reference it
from the README. Keep the `.excalidraw` file committed — it is the editable
original, and an exported image alone cannot be revised.

## Keeping it honest

The rule ladder in this diagram mirrors `envs/dev/rules.tf` and
`envs/prod/rules.tf`. If you change a rule's mode, change it here too — a
diagram that disagrees with the code is worse than no diagram, and it is the
kind of thing an interviewer notices.
