<p align="center">
  <img src="assets/logo.png" alt="Cold Hash Checker logo" width="200">
</p>

# Cold Hash Checker

The tool calculates MD5, SHA-1, and SHA-256 hashes for files and checks each
SHA-256 value against `database/known_hashes.json`.

Start the interactive menu with:

```powershell
python main.py
```

On Windows you can also double-click `start.bat`.

The menu can analyze a single file, scan a directory recursively, show how
many hashes are loaded from the database, and add a file's SHA-256 to the
database. Reports are saved as JSON in the `reports` directory.

Requires Python 3.8+ and no external packages.

The database must be a JSON object whose keys are SHA-256 hashes. Values may
contain optional metadata for a matching hash. For example:

```json
{
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
    "name": "empty file"
  }
}
```

Matching files are marked `KNOWN`; unmatched files are marked `UNKNOWN`. Files
that cannot be read during a directory scan are reported as `ERROR`.