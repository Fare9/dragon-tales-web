# dragon-tales-web

Source for the dragon-tales project site and manual, built with [Hugo](https://gohugo.io) (extended, v0.164.0+).

## Local development

```sh
hugo server
```

Serves at `http://localhost:1313/dragon-tales-web/`, rebuilding on save.

## Build

```sh
hugo --gc --minify
```

Output lands in `public/`.

## Structure

```
content/            page content (Markdown)
  _index.md          home page — about the project
  manual/             the manual, one file per chapter
layouts/             Hugo templates
  shortcodes/          compare.html + pane.html — the C++/Python comparison slider
assets/css/          site theme + Chroma syntax-highlighting overrides
static/js/           vendored img-comparison-slider web component
```

## Deployment

`.github/workflows/hugo.yml` builds and deploys to GitHub Pages on every
push to `main`. Enable Pages for this repo under **Settings → Pages →
Source: GitHub Actions**.
