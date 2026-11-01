# Assets

| File | Use |
|---|---|
| `logo.svg` | square mark, 512×512 — repository avatar, About screen |
| `banner.svg` | 1280×320 wordmark for the README and release pages |
| `footer.svg` | 1200×220 dark responsibility card used at the end of the README |
| `app.ico` / `app.png` | window and taskbar icon (16–256 px) |

All three are hand-written SVG with no external fonts or embedded images, so they
scale cleanly and render in GitHub's image proxy.

Palette (matches the application theme in `nulltrace/theme.py`):

| Role | Hex |
|---|---|
| background | `#08080a` |
| panel | `#0d0d0f` |
| card | `#101012` |
| text | `#eae8e4` |
| muted | `#9a9791` |
| signal red | `#e23b3b` |
| border | `#9a2f34` (cards `#5f2024`) |

Light mode (full white, black borders):

| Role | Hex |
|---|---|
| background | `#ffffff` |
| panel | `#fafafa` |
| text | `#000000` |
| muted | `#2b2b2b` |
| signal red | `#c62828` |
| border | `#000000` (cards `#3c3c3c`) |

To generate a Windows icon from the mark:

```powershell
# requires ImageMagick
magick -background none assets/logo.svg -define icon:auto-resize=256,128,64,48,32,16 assets/nulltrace.ico
```
