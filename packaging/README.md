# Packaging

Build a self-contained Windows build that runs without Python installed.

```powershell
powershell -ExecutionPolicy Bypass -File packaging\build_windows.ps1 -Version 1.0.0
```

Output:

```
dist\Null-Trace\Null-Trace.exe     portable folder
dist\Null-Trace-1.0.0-win64.zip    shareable archive
```

## What the spec does

- entry point `scan.py`, no console window (`console=False`);
- bundles `data/` so wordlists and dork catalogs still work;
- collects customtkinter assets and the DNS, phone, QR and test packages;
- excludes `unittest`, `test` and `tkinter.test` to keep the size down.

## Notes

- The build is **unsigned**. SmartScreen will warn on first launch; users can
  choose "More info → Run anyway", or you can sign the executable with a code
  signing certificate.
- Antivirus heuristics sometimes flag PyInstaller binaries. Building from source
  (`run.bat`) avoids that.
- macOS and Linux builds are not scripted. They work with the same spec:
  `python -m PyInstaller packaging/nulltrace.spec`, then run the folder in
  `dist/`.
- Bump `VERSION` in `nulltrace/version.py` before a release and tag the commit.
