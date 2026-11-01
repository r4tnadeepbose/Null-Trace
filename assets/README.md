# Assets

| File | Use |
|---|---|
| `logo.svg` | square mark, 512×512 — repository avatar, About screen |
| `banner.svg` | 1280×320 wordmark for the README and release pages |
| `footer.svg` | 1200×220 dark responsibility card used at the end of the README |
| `app.ico` / `app.png` | window and taskbar icon (16–256 px) |

Both are hand-written SVG with no external fonts or embedded images, so they
scale cleanly and render in GitHub's image proxy.

Palette (matches the application theme in `nulltrace/theme.py`):

| Role | Hex |
|---|---|
| background | `#111318` |
| panel | `#171a21` |
| parchment text | `#e7e2d8` |
| muted blue accent | `#7fa0c4` |
| highlight | `#93b4d6` |
| border | `#2d333f` |

To generate a Windows icon from the mark:

```powershell
# requires ImageMagick
magick -background none assets/logo.svg -define icon:auto-resize=256,128,64,48,32,16 assets/nulltrace.ico
```
