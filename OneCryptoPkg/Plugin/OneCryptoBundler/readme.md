# OneCryptoPkg Scripts

This directory contains utility scripts for working with OneCryptoPkg.

## Testing Local Changes

To test local OneCrypto binary changes in your platform without publishing to a remote server:

### 1. Build OneCryptoPkg

Build the OneCryptoPkg binaries using your normal build process (e.g., `stuart_build`).

This will automatically package the binaries, though you can manually bundle via

```powershell
python OneCryptoPkg\Plugin\OneCryptoBundler\OneCryptoBundler.py
```

The log file will contain the SHA256 of the bundled package.

### 2. Start a Local HTTP Server

From the `Build` directory, start a simple HTTP server:

```powershell
cd Build
python -m http.server
```

This serves files on `http://localhost:8000`.

### 4. Update Your Platform's ext_dep.json

Copy the contents from `OneCrypto_ext_dep.json.template` and replace:

- `<sha256 from package_onecrypto.py>` with the SHA256 hash from step 1

Add this to your platform's ext_dep.json file (or update the existing OneCrypto entry).

### 5. Update Dependencies

Run stuart_update in your platform to fetch the locally-served package:

```powershell
stuart_update -c <your_platform>.py
```

Your platform will now use the locally built OneCrypto binaries for testing.
