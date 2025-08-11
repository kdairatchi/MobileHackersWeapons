#!/usr/bin/env python3
"""
Mobile Bug Bounty Toolkit (bbt)
A unified CLI for APK/IPA search, download, install, extraction, analysis, and reporting.

Core highlights:
- Multi-source APK search: F-Droid (API), APKPure, APKMirror (browser integration), and Play web pages.
- Direct F-Droid downloads via official APIs and repo file naming.
- Android device ops via adb: install/bulk-install, extract APKs, backup user apps, live permission analysis, pkg info.
- iOS IPA management: list/install (via external tools), extract, analyze (Info.plist, URL schemes, code signature, provisioning profiles, otool).
- App store analysis: version history for F-Droid, Play/third-party browsing, similar apps discovery (browser).
- Batch analysis and inventory reports, hash and certificate utilities, JSON prettify, Base64 encode/decode.

Ethical/legal: Use only on apps and devices you own or are explicitly authorized to test. Respect store and site Terms of Service. Do not circumvent DRM or security controls.
"""

import os, sys, re, json, base64, hashlib, zipfile, plistlib, shutil, webbrowser
import subprocess, shlex, tempfile
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Tuple, Dict

# Optional third-party modules (nice-to-have)
try:
    import requests
except Exception:
    requests = None

try:
    import click
except Exception:
    print("Please `pip install click requests` to use this toolkit.")
    sys.exit(1)

# ---------- Helpers ----------

def run_cmd(cmd: List[str], timeout: int = 300) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return 127, "", f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"Timeout running: {' '.join(cmd)}"

def which(bin_name: str) -> Optional[str]:
    return shutil.which(bin_name)

def ensure_requests():
    if requests is None:
        raise RuntimeError("The 'requests' library is required. Install with: pip install requests")

def http_get(url: str, params: Dict = None, headers: Dict = None, stream: bool = False):
    ensure_requests()
    ua = {"User-Agent": "bbt/1.0 (+security-research)"}
    if headers:
        ua.update(headers)
    resp = requests.get(url, params=params, headers=ua, timeout=60, stream=stream)
    resp.raise_for_status()
    return resp

def save_stream(resp, out_path: Path):
    with open(out_path, "wb") as f:
        for chunk in resp.iter_content(chunk_size=65536):
            if chunk:
                f.write(chunk)

def calc_hashes(path: Path) -> Dict[str, str]:
    hs = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    with open(path, "rb") as f:
        while True:
            b = f.read(1024 * 1024)
            if not b:
                break
            for h in hs.values():
                h.update(b)
    return {k: v.hexdigest() for k, v in hs.items()}

def pretty_json(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True)

def require_tool(bin_name: str, hint: str):
    if not which(bin_name):
        raise click.ClickException(f"Missing required tool: {bin_name}. {hint}")

# ---------- F-Droid Integration (documented APIs) ----------
# Docs: https://f-droid.org/docs/All_our_APIs/
FDROID_SEARCH_API = "https://search.f-droid.org/api/search_apps"
FDROID_PACKAGE_API = "https://f-droid.org/api/v1/packages"
FDROID_REPO = "https://f-droid.org/repo"
FDROID_ARCHIVE = "https://f-droid.org/archive"

def fdroid_search(query: str, limit: int = 20) -> List[Dict]:
    # Full-text search
    resp = http_get(FDROID_SEARCH_API, params={"q": query})
    data = resp.json()
    # API returns array of apps with metadata; keep top N
    return data[:limit]

def fdroid_package_info(appid: str) -> Dict:
    resp = http_get(f"{FDROID_PACKAGE_API}/{appid}")
    return resp.json()

def fdroid_apk_url(appid: str, version_code: int, archived: bool = False) -> str:
    # Based on F-Droid’s published naming convention: <ApplicationId>_<VersionCode>.apk
    # See reproducible build logs and index docs (linked above).
    base = FDROID_ARCHIVE if archived else FDROID_REPO
    return f"{base}/{appid}_{version_code}.apk"

def fdroid_try_download(appid: str, version_code: int, out_dir: Path) -> Path:
    # Try repo first, then archive fall-back
    for archived in (False, True):
        url = fdroid_apk_url(appid, version_code, archived=archived)
        try:
            resp = http_get(url, stream=True)
            out_path = out_dir / f"{appid}_{version_code}.apk"
            save_stream(resp, out_path)
            return out_path
        except Exception:
            continue
    raise click.ClickException(f"Could not fetch APK for {appid} v{version_code} from F-Droid repo or archive.")

# ---------- APKPure/APKMirror browser helpers ----------
def apkpure_search(query: str):
    # Browser integration for browsing/downloading
    url = f"https://apkpure.com/search?q={requests.utils.quote(query) if requests else query}"
    webbrowser.open(url)

def apkmirror_search(query: str):
    # Browser integration; APKMirror supports searching by term
    url = f"https://www.apkmirror.com/?post_type=app&s={requests.utils.quote(query) if requests else query}"
    webbrowser.open(url)

# ---------- Google Play (web pages) ----------
def play_search(query: str):
    url = f"https://play.google.com/store/search?q={requests.utils.quote(query) if requests else query}&c=apps"
    webbrowser.open(url)

def play_open_app(appid: str):
    url = f"https://play.google.com/store/apps/details?id={appid}"
    webbrowser.open(url)

# ---------- Android Device Ops (adb, aapt, apksigner) ----------
def adb_devices() -> List[str]:
    code, out, err = run_cmd(["adb", "devices"])
    if code != 0:
        raise click.ClickException(err.strip() or "adb error")
    lines = out.strip().splitlines()[1:]
    return [l.split()[0] for l in lines if l.strip() and "\tdevice" in l]

def adb_install(apk: Path, replace: bool = True, device: Optional[str] = None) -> str:
    cmd = ["adb"]
    if device:
        cmd += ["-s", device]
    cmd += ["install"]
    if replace:
        cmd += ["-r"]
    cmd += [str(apk)]
    code, out, err = run_cmd(cmd, timeout=1800)
    if code != 0:
        raise click.ClickException(err.strip() or out or "adb install failed")
    return out.strip()

def adb_list_user_packages(device: Optional[str] = None) -> List[str]:
    cmd = ["adb"]
    if device:
        cmd += ["-s", device]
    cmd += ["shell", "pm", "list", "packages", "-3"]
    code, out, err = run_cmd(cmd)
    if code != 0:
        raise click.ClickException(err.strip() or out or "adb pm list failed")
    pkgs = []
    for line in out.splitlines():
        m = re.match(r"package:(.+)", line.strip())
        if m:
            pkgs.append(m.group(1))
    return pkgs

def adb_pkg_path(pkg: str, device: Optional[str] = None) -> Optional[str]:
    cmd = ["adb"]
    if device:
        cmd += ["-s", device]
    cmd += ["shell", "pm", "path", pkg]
    code, out, err = run_cmd(cmd)
    if code != 0:
        return None
    m = re.search(r"package:(\S+)", out)
    return m.group(1) if m else None

def adb_pull(remote: str, local: Path, device: Optional[str] = None) -> bool:
    cmd = ["adb"]
    if device:
        cmd += ["-s", device]
    cmd += ["pull", remote, str(local)]
    code, out, err = run_cmd(cmd, timeout=1800)
    return code == 0

def aapt_dump_permissions(apk: Path) -> List[str]:
    # Requires Android build-tools 'aapt' or 'apkanalyzer'. Prefer aapt for simplicity.
    aapt_bin = which("aapt") or which("aapt2")
    if not aapt_bin:
        return []
    code, out, err = run_cmd([aapt_bin, "dump", "badging", str(apk)])
    if code != 0:
        return []
    perms = re.findall(r"uses-permission(?:-sdk-23)?:name='([^']+)'", out)
    return sorted(set(perms))

def aapt_dump_schemes(apk: Path) -> List[str]:
    aapt_bin = which("aapt") or which("aapt2")
    if not aapt_bin:
        return []
    code, out, err = run_cmd([aapt_bin, "dump", "xmltree", str(apk), "AndroidManifest.xml"])
    if code != 0:
        return []
    schemes = set()
    for line in out.splitlines():
        line = line.strip()
        if "A: android:scheme" in line:
            m = re.search(r'"([^"]+)"', line)
            if m:
                schemes.add(m.group(1))
    return sorted(schemes)

def apksigner_certs(apk: Path) -> str:
    apksigner = which("apksigner")
    if not apksigner:
        return "apksigner not found."
    code, out, err = run_cmd([apksigner, "verify", "--print-certs", str(apk)])
    return (out + "\n" + err).strip()

def android_live_permission_analysis(pkg: str, device: Optional[str] = None) -> Dict[str, List[str]]:
    cmd = ["adb"]
    if device:
        cmd += ["-s", device]
    cmd += ["shell", "dumpsys", "package", pkg]
    code, out, err = run_cmd(cmd)
    if code != 0:
        raise click.ClickException(err.strip() or out or "dumpsys failed")
    requested = re.findall(r"android.permission.[A-Z0-9_.]+", out)
    granted = re.findall(r"granted=true\): ([a-zA-Z0-9._]+)", out)  # heuristic
    granted2 = re.findall(r"granted=true", out)
    # Better parse: look for "granted=true" alongside permission lines
    granted_perms = []
    for block in re.split(r"\n\s*\n", out):
        if "android.permission." in block and "granted=" in block:
            m1 = re.search(r"name=(android.permission.[A-Z0-9_.]+)", block)
            m2 = re.search(r"granted=(true|false)", block)
            if m1 and m2 and m2.group(1) == "true":
                granted_perms.append(m1.group(1))
    return {
        "requested": sorted(set(requested)),
        "granted": sorted(set(granted_perms)),
    }

# ---------- IPA Handling (extract, analyze, install guidance) ----------
def ipa_extract(ipa: Path, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(ipa, "r") as z:
        z.extractall(out_dir)
    return out_dir

def find_app_bundle(extracted_dir: Path) -> Optional[Path]:
    payload = extracted_dir / "Payload"
    if not payload.exists():
        # Some IPAs include a top-level folder; search recursively a bit
        for p in extracted_dir.glob("**/Payload"):
            payload = p
            break
    if not payload.exists():
        return None
    apps = list(payload.glob("*.app"))
    return apps[0] if apps else None

def read_info_plist(app_bundle: Path) -> Dict:
    plist_path = app_bundle / "Info.plist"
    with open(plist_path, "rb") as f:
        return plistlib.load(f)

def extract_url_schemes(info: Dict) -> List[str]:
    schemes = []
    url_types = info.get("CFBundleURLTypes", [])
    for t in url_types:
        for s in t.get("CFBundleURLSchemes", []):
            schemes.append(s)
    return schemes

def codesign_verify(app_bundle: Path) -> str:
    if not which("codesign"):
        return "codesign not available on this system."
    code, out, err = run_cmd(["codesign", "-dv", "--verbose=4", str(app_bundle)])
    return (out + "\n" + err).strip()

def provisioning_profile_info(app_bundle: Path) -> Dict:
    prof = app_bundle / "embedded.mobileprovision"
    if not prof.exists():
        return {"note": "No embedded.mobileprovision found."}
    # Decode provisioning profile (CMS/PKCS7) via macOS 'security'
    if not which("security"):
        return {"note": "security tool not available to decode provisioning profile."}
    code, out, err = run_cmd(["security", "cms", "-D", "-i", str(prof)])
    if code != 0:
        return {"error": err or out}
    try:
        return plistlib.loads(out.encode("utf-8"))
    except Exception:
        # Sometimes 'security cms -D' prints XML plist; plistlib can load from bytes either way
        try:
            return plistlib.loads(out.encode())
        except Exception:
            return {"raw": out}

def otool_macho_info(app_bundle: Path) -> str:
    if not which("otool"):
        return "otool not available."
    # Inspect main binary for linked libs
    # Heuristic: main executable is CFBundleExecutable inside the .app
    info = read_info_plist(app_bundle)
    exe = info.get("CFBundleExecutable")
    if not exe:
        return "CFBundleExecutable not found."
    bin_path = app_bundle / exe
    code, out, err = run_cmd(["otool", "-L", str(bin_path)])
    return (out + "\n" + err).strip()

def idevice_install(ipa: Path, udid: Optional[str] = None) -> str:
    if not which("ideviceinstaller"):
        return "ideviceinstaller not found. Alternatively use AltStore/Sideloadly/3uTools."
    cmd = ["ideviceinstaller"]
    if udid:
        cmd += ["-u", udid]
    cmd += ["-i", str(ipa)]
    code, out, err = run_cmd(cmd, timeout=1800)
    if code != 0:
        return (err or out or "Install failed").strip()
    return out.strip()

# ---------- Reporting ----------
def build_inventory(dir_path: Path) -> Dict:
    inventory = {"generated_at": datetime.utcnow().isoformat() + "Z", "apks": [], "ipas": []}
    for p in dir_path.rglob("*.apk"):
        h = calc_hashes(p)
        pkg = {"path": str(p), "md5": h["md5"], "sha1": h["sha1"], "sha256": h["sha256"], "permissions": aapt_dump_permissions(p), "url_schemes": aapt_dump_schemes(p)}
        inventory["apks"].append(pkg)
    for p in dir_path.rglob("*.ipa"):
        h = calc_hashes(p)
        pkg = {"path": str(p), "md5": h["md5"], "sha1": h["sha1"], "sha256": h["sha256"]}
        inventory["ipas"].append(pkg)
    return inventory

# ---------- CLI ----------
@click.group()
def cli():
    pass

# Search
@cli.group()
def search():
    """Search apps across sources."""
    pass

@search.command("fdroid")
@click.argument("query", nargs=-1, required=True)
@click.option("--limit", default=20, show_default=True)
def search_fdroid(query, limit):
    """Search F-Droid repository via API."""
    q = " ".join(query)
    try:
        results = fdroid_search(q, limit=limit)
    except Exception as e:
        raise click.ClickException(str(e))
    if not results:
        click.echo("No results.")
        return
    for app in results:
        # Typical fields: packageName, name, summary
        click.echo(f"{app.get('packageName','?')} - {app.get('name','?')}: {app.get('summary','').strip()[:120]}")

@search.command("apkpure")
@click.argument("query", nargs=-1, required=True)
def search_apkpure(query):
    """Open APKPure search in your browser."""
    q = " ".join(query)
    apkpure_search(q)
    click.echo("Opened APKPure in browser.")

@search.command("apkmirror")
@click.argument("query", nargs=-1, required=True)
def search_apkmirror(query):
    """Open APKMirror search in your browser."""
    q = " ".join(query)
    apkmirror_search(q)
    click.echo("Opened APKMirror in browser.")

@search.command("play")
@click.argument("query", nargs=-1, required=True)
def search_play(query):
    """Open Google Play search in your browser."""
    q = " ".join(query)
    play_search(q)
    click.echo("Opened Google Play in browser.")

@search.command("all")
@click.argument("query", nargs=-1, required=True)
@click.option("--limit", default=10, show_default=True, help="Limit for F-Droid API results.")
def search_all(query, limit):
    """Multi-source search: F-Droid results in terminal; open APKPure/APKMirror/Play in browser."""
    q = " ".join(query)
    try:
        res = fdroid_search(q, limit=limit)
        click.echo("[F-Droid]")
        for app in res:
            click.echo(f"  {app.get('packageName','?')} - {app.get('name','?')}")
    except Exception:
        click.echo("F-Droid API lookup failed.")
    apkpure_search(q)
    apkmirror_search(q)
    play_search(q)
    click.echo("Opened APKPure, APKMirror, and Play in browser.")

# F-Droid Download
@cli.group()
def fdroid():
    """F-Droid specific actions (download, versions)."""
    pass

@fdroid.command("versions")
@click.argument("appid")
def fdroid_versions(appid):
    """List published/suggested versions for an app."""
    try:
        info = fdroid_package_info(appid)
    except Exception as e:
        raise click.ClickException(str(e))
    click.echo(pretty_json(info))

@fdroid.command("download")
@click.argument("appid")
@click.option("--version-code", type=int, help="Specific versionCode to download. If omitted, uses suggestedVersionCode.")
@click.option("--out", type=click.Path(path_type=Path), default=Path("downloads"))
def fdroid_download(appid, version_code, out):
    """Directly download APK from F-Droid repo/archive and save to disk."""
    out.mkdir(parents=True, exist_ok=True)
    try:
        info = fdroid_package_info(appid)
        vcode = version_code or info.get("suggestedVersionCode")
        if not vcode:
            raise click.ClickException("Could not determine versionCode; specify --version-code.")
        apk_path = fdroid_try_download(appid, int(vcode), out)
    except Exception as e:
        raise click.ClickException(str(e))
    h = calc_hashes(apk_path)
    click.echo(f"Saved: {apk_path}")
    click.echo(f"SHA256: {h['sha256']}")

# Android ops
@cli.group()
def android():
    """Android device operations via adb."""
    pass

@android.command("devices")
def android_devices():
    devs = adb_devices()
    if not devs:
        click.echo("No devices found.")
    else:
        for d in devs:
            click.echo(d)

@android.command("install")
@click.argument("apk", type=click.Path(path_type=Path, exists=True))
@click.option("--device", help="Specific device serial.")
@click.option("--no-replace", is_flag=True, help="Do not replace if already installed.")
def android_install(apk, device, no_replace):
    out = adb_install(apk, replace=not no_replace, device=device)
    click.echo(out)

@android.command("install-bulk")
@click.argument("folder", type=click.Path(path_type=Path, exists=True))
@click.option("--device", help="Device serial.")
def android_install_bulk(folder, device):
    apks = list(Path(folder).glob("*.apk"))
    if not apks:
        click.echo("No APKs in folder.")
        return
    for i, apk in enumerate(apks, 1):
        click.echo(f"[{i}/{len(apks)}] Installing {apk.name} ...")
        try:
            out = adb_install(apk, device=device)
            click.echo(out)
        except click.ClickException as e:
            click.echo(f"Failed: {e}")

@android.command("extract-apk")
@click.argument("package")
@click.option("--out", type=click.Path(path_type=Path), default=Path("device_apks"))
@click.option("--device", help="Device serial.")
def android_extract_apk(package, out, device):
    out.mkdir(parents=True, exist_ok=True)
    path = adb_pkg_path(package, device=device)
    if not path:
        raise click.ClickException("Could not determine APK path on device.")
    dest = out / f"{package}.apk"
    ok = adb_pull(path, dest, device=device)
    if not ok:
        raise click.ClickException("adb pull failed.")
    h = calc_hashes(dest)
    click.echo(f"Saved: {dest}\nSHA256: {h['sha256']}")

@android.command("backup-user-apps")
@click.option("--out", type=click.Path(path_type=Path), default=Path("device_apks"))
@click.option("--device", help="Device serial.")
def android_backup_user(out, device):
    out.mkdir(parents=True, exist_ok=True)
    pkgs = adb_list_user_packages(device=device)
    if not pkgs:
        click.echo("No user apps found.")
        return
    for i, pkg in enumerate(pkgs, 1):
        click.echo(f"[{i}/{len(pkgs)}] {pkg}")
        path = adb_pkg_path(pkg, device=device)
        if not path:
            click.echo("  Skipping, no path.")
            continue
        dest = out / f"{pkg}.apk"
        if adb_pull(path, dest, device=device):
            click.echo(f"  -> {dest}")
        else:
            click.echo("  Pull failed.")

@android.command("perms-live")
@click.argument("package")
@click.option("--device", help="Device serial.")
def android_perms_live(package, device):
    res = android_live_permission_analysis(package, device=device)
    click.echo("Requested permissions:")
    for p in res["requested"]:
        click.echo(f"  {p}")
    click.echo("Granted permissions:")
    for p in res["granted"]:
        click.echo(f"  {p}")

@android.command("pkg-info")
@click.argument("apk", type=click.Path(path_type=Path, exists=True))
def android_pkg_info(apk):
    perms = aapt_dump_permissions(apk)
    schemes = aapt_dump_schemes(apk)
    click.echo(pretty_json({"permissions": perms, "url_schemes": schemes, "hashes": calc_hashes(apk)}))
    click.echo("\nCertificate info (apksigner):")
    click.echo(apksigner_certs(apk))

# iOS ops
@cli.group()
def ios():
    """iOS IPA management and analysis."""
    pass

@ios.command("list")
@click.argument("folder", type=click.Path(path_type=Path, exists=True))
def ios_list(folder):
    ipas = list(Path(folder).rglob("*.ipa"))
    for p in ipas:
        click.echo(p)

@ios.command("install")
@click.argument("ipa", type=click.Path(path_type=Path, exists=True))
@click.option("--udid", help="Target device UDID (ideviceinstaller).")
@click.option("--method", type=click.Choice(["ideviceinstaller", "altstore", "sideloadly", "3utools", "cydia-impactor"]), default="ideviceinstaller", show_default=True)
def ios_install(ipa, udid, method):
    if method == "ideviceinstaller":
        click.echo(idevice_install(ipa, udid=udid))
    else:
        click.echo(f"Use {method} GUI to sideload {ipa}. This toolkit focuses on analysis and will open docs soon.")
        # You can expand: launch instructions or URLs here.

@ios.command("extract")
@click.argument("ipa", type=click.Path(path_type=Path, exists=True))
@click.option("--out", type=click.Path(path_type=Path), default=Path("extracted"))
def ios_extract(ipa, out):
    dest = Path(out) / Path(ipa).stem
    ipa_extract(ipa, dest)
    app = find_app_bundle(dest)
    click.echo(f"Extracted to: {dest}")
    if app:
        click.echo(f"App bundle: {app}")

@ios.command("analyze")
@click.argument("ipa", type=click.Path(path_type=Path, exists=True))
@click.option("--print-entitlements", is_flag=True, help="Attempt to print entitlements via codesign (macOS).")
def ios_analyze(ipa, print_entitlements):
    tmp = Path(tempfile.mkdtemp(prefix="bbt_ipa_"))
    try:
        ipa_extract(ipa, tmp)
        app = find_app_bundle(tmp)
        if not app:
            raise click.ClickException("Could not locate .app bundle in IPA.")
        info = read_info_plist(app)
        schemes = extract_url_schemes(info)
        click.echo("Info.plist:")
        click.echo(pretty_json(info))
        click.echo("\nURL Schemes:")
        for s in schemes:
            click.echo(f"  {s}")
        click.echo("\nCode signature:")
        click.echo(codesign_verify(app))
        if print_entitlements and which("codesign"):
            code, out, err = run_cmd(["codesign", "-d", "--entitlements", ":-", str(app)])
            click.echo("\nEntitlements:")
            click.echo(out or err)
        click.echo("\notool (linked libraries):")
        click.echo(otool_macho_info(app))
        click.echo("\nProvisioning profile (if any):")
        pp = provisioning_profile_info(app)
        if isinstance(pp, dict):
            click.echo(pretty_json(pp))
        else:
            click.echo(str(pp))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

# Cydia packages (generic web search aggregator)
@cli.group()
def cydia():
    """Cydia/Sileo package discovery assistance (opens browser)."""
    pass

@cydia.command("search")
@click.argument("query", nargs=-1, required=True)
def cydia_search(query):
    q = " ".join(query)
    # Open a general web search to cover multiple repos; users can add specific repos they use.
    webbrowser.open(f"https://duckduckgo.com/?q=cydia+package+{q}")
    click.echo("Opened web search for Cydia packages in your browser.")

# App store analysis openers
@cli.group()
def store():
    """App store lookups and analysis helpers."""
    pass

@store.command("play-open")
@click.argument("appid")
def store_play_open(appid):
    play_open_app(appid)
    click.echo("Opened Google Play app page.")

@store.command("similar")
@click.argument("appid")
def store_similar(appid):
    # Opens Play page; the Similar section is easy to browse.
    play_open_app(appid)
    click.echo("Browse the Similar section in your browser.")

@store.command("fdroid-history")
@click.argument("appid")
def store_fdroid_history(appid):
    info = fdroid_package_info(appid)
    click.echo(pretty_json(info))

# Utilities
@cli.group()
def util():
    """Utility commands: hashes, certs, jsonfmt, base64."""
    pass

@util.command("hash")
@click.argument("file", type=click.Path(path_type=Path, exists=True))
def util_hash(file):
    h = calc_hashes(file)
    click.echo(pretty_json(h))

@util.command("apk-cert")
@click.argument("apk", type=click.Path(path_type=Path, exists=True))
def util_apk_cert(apk):
    click.echo(apksigner_certs(apk))

@util.command("jsonfmt")
@click.argument("infile", type=click.Path(path_type=Path, exists=True))
def util_jsonfmt(infile):
    with open(infile, "rb") as f:
        data = json.load(f)
    click.echo(pretty_json(data))

@util.command("b64enc")
@click.argument("infile", type=click.Path(path_type=Path, exists=True))
def util_b64enc(infile):
    with open(infile, "rb") as f:
        b = f.read()
    click.echo(base64.b64encode(b).decode())

@util.command("b64dec")
@click.argument("data")
@click.option("--out", type=click.Path(path_type=Path))
def util_b64dec(data, out):
    try:
        raw = base64.b64decode(data)
    except Exception as e:
        raise click.ClickException(f"Invalid base64: {e}")
    if out:
        with open(out, "wb") as f:
            f.write(raw)
        click.echo(f"Wrote {out}")
    else:
        sys.stdout.buffer.write(raw)

# Bulk/Batch
@cli.group()
def batch():
    """Batch operations over folders."""
    pass

@batch.command("analyze-apks")
@click.argument("folder", type=click.Path(path_type=Path, exists=True))
def batch_analyze_apks(folder):
    folder = Path(folder)
    results = []
    for apk in folder.rglob("*.apk"):
        perms = aapt_dump_permissions(apk)
        schemes = aapt_dump_schemes(apk)
        results.append({"apk": str(apk), "permissions": perms, "url_schemes": schemes, "hashes": calc_hashes(apk)})
    click.echo(pretty_json(results))

@batch.command("report")
@click.argument("folder", type=click.Path(path_type=Path, exists=True))
@click.option("--out", type=click.Path(path_type=Path), default=Path("app_inventory.json"))
def batch_report(folder, out):
    inv = build_inventory(Path(folder))
    with open(out, "w", encoding="utf-8") as f:
        json.dump(inv, f, ensure_ascii=False, indent=2)
    click.echo(f"Wrote report to {out}")

if __name__ == "__main__":
    cli()