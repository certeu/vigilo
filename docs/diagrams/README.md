# README diagrams

The three architecture diagrams in `docs/images/` (`modes-overview`, `whitebox-flow`,
`whitebox-detail`) are drawn with
[Manim](https://www.manim.community/), one scene per file, sharing the palette and drawing
helpers in `style.py`.

Re-render them all (or name scenes, e.g. `WhiteboxDetail`) with:

```bash
docs/diagrams/render.sh
```

Manim is not a project dependency: the script runs it in an isolated `uv` environment
(`uv run --no-project --with manim`) and writes ~3600 px wide PNGs straight into `docs/images/`.
It needs the cairo and pango system libraries (on macOS: `brew install cairo pango pkgconf`),
no LaTeX. Set `VIGILO_DIAGRAM_FONT` to use a font other than Helvetica.
