#!/usr/bin/env python3
"""
Mobile Bug Bounty Toolkit (bbt)
A unified CLI for APK/IPA search, download, install, extraction, analysis, and reporting.

New automation highlights:
- Robust HTTP with retries and timeouts (less flaky network ops).
- Parallelism: --jobs N for faster bulk installs/analysis.
- F-Droid offline index cache and fallback search when API fails.
- Smart installs: only install APKs that are newer than what the device has.
- Permission diff: compare requested permissions between two APKs (added/removed/unchanged).
- Automated cleanup: delete old APK/IPA files by age pattern.
- Verbose logging and safer tool checks with friendly hints.

Ethical/legal: Use only on apps/devices you own or are authorized to test. Respect Terms of Service. Do not circumvent DRM or security controls.
"""

import os, sys, re, json, base64, hashlib, zipfile, plistlib, shutil, webbrowser, time
import subprocess, tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Optional, Tuple, Dict

# Optional third-party modules
try:
    import requests
except Exception:
    requests = None

try:
    import click
except Exception:
    print("Please `pip install click requests` to use this toolkit.")
    sys.exit(1)

# ---------- Globals / Logging ----------

DEFAULT_TIMEOUT = 60
DEFAULT_RETRIES = 3
CACHE_DIR = Path.home() / ".bbt_cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

def which(bin_name: str) -> Optional[str]:
    return shutil.which(bin_name)

def log(msg: str, level: str = "info"):
    # Respect --verbose: print debug; otherwise info/warn/error only.
    ctx = click.get_current_context(silent=True)
    verbose = bool(ctx and ctx.obj and ctx.obj.get("verbose"))
    if level == "debug" and not verbose:
        return
    prefix = {"debug": "[DEBUG] ", "info": "", "warn": "[WARN] ", "error": "[ERROR] "}.get(level, "")
    click.echo(prefix + msg)

def require_tool(bin_name: str, hint: str):
    if not which(bin_name):
        raise click.ClickException(f"Missing required tool: {bin_name}. {hint}")

def run_cmd(cmd: List[str], timeout: int = 300) -> Tuple[int, str, str]:
    log(f"Running: {' '.join(cmd)}", "debug")
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return 127, "", f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"Timeout running: {' '.join(cmd)}"

# ---------- HTTP ----------

def ensure_requests():
    if requests is None:
        raise RuntimeError("The 'requests' library is required. Install with: pip install requests")

def http_get(url: str, params: Dict = None, headers: Dict = None, stream: bool = False, retries: int = DEFAULT_RETRIES, timeout: int = DEFAULT_TIMEOUT):
    ensure_requests()
    ua = {"User-Agent": "bbt/1.1 (+security-research)"}
    if headers:
        ua.update(headers)
    last_exc = None
    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(url, params=params, headers=ua, timeout=timeout, stream=stream)
            resp.raise_for_status()
            return resp
        except Exception as e:
            last_exc = e
            wait = min(2 ** (attempt - 1), 8)
            log(f"HTTP GET failed (attempt {attempt}/{retries}) for {url}: {e}. Retrying in {wait}s...", "warn")
            time.sleep(wait)
    raise click.ClickException(f"Failed to GET {url}: {last_exc}")

def save_stream(resp, out_path: Path):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "wb") as f:
        for chunk in resp.iter_content(chunk_size=65536):
            if chunk:
                f.write(chunk)

# ---------- Hashes / JSON ----------

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

# ---------- F-Droid Integration ----------
# Docs: https://f-droid.org/docs/All_our_APIs/
FDROID_SEARCH_API = "https://search.f-droid.org/api/search_apps"
FDROID_PACKAGE_API = "https://f-droid.org/api/v1/packages"
FDROID_REPO = "https://f-droid.org/repo"
FDROID_ARCHIVE = "https://f-droid.org/archive"
FDROID_INDEX_V2 = f"{FDROID_REPO}/index-v2.json"
FDROID_INDEX_CACHE = CACHE_DIR / "fdroid_index_v2.json"

def fdroid_search_api(query: str, limit: int = 20) -> List[Dict]:
    resp = http_get(FDROID_SEARCH_API, params={"q": query})
    data = resp.json()
    return data[:limit]

def fdroid_package_info(appid: str) -> Dict:
    resp = http_get(f"{FDROID_PACKAGE_API}/{appid}")
    return resp.json()

def fdroid_apk_url(appid: str, version_code: int, archived: bool = False) -> str:
    base = FDROID_ARCHIVE if archived else FDROID_REPO
    return f"{base}/{appid}_{version_code}.apk"

def fdroid_try_download(appid: str, version_code: int, out_dir: Path) -> Path:
    for archived in (False, True):
        url = fdroid_apk_url(appid, version_code, archived=archived)
        try:
            resp = http_get(url, stream=True)
            out_path = out_dir / f"{appid}_{version_code}.apk"
            save_stream(resp, out_path)
            return out_path
        except Exception as e:
            log(f"Download attempt failed from {'archive' if archived else 'repo'}: {e}", "debug")
    raise click.ClickException(f"Could not fetch APK for {appid} v{version_code} from F-Droid repo or archive.")

def fdroid_index_cache_update() -> Path:
    log("Fetching F-Droid index-v2.json ...", "info")
    resp = http_get(FDROID_INDEX_V2, stream=False, timeout=120)
    data = resp.json()
    FDROID_INDEX_CACHE.write_text(json.dumps(data), encoding="utf-8")
    log(f"Cached F-Droid index at {FDROID_INDEX_CACHE}", "info")
    return FDROID_INDEX_CACHE

def fdroid_index_load() -> Optional[Dict]:
    if not FDROID_INDEX_CACHE.exists():
        return None
    try:
        with open(FDROID_INDEX_CACHE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def fdroid_search_offline(index: Dict, query: str, limit: int = 20) -> List[Dict]:
    q = query.lower()
    results = []
    apps = index.get("packages", {}) if isinstance(index, dict) else {}
    # index-v2.json has structure: {"packages": {"appid": {...}}}
    for appid, meta in apps.items():
        name = meta.get("name", "")
        summary = meta.get("summary", "")
        if q in appid.lower() or q in name.lower() or q in summary.lower():
            results.append({"packageName": appid, "name": name, "summary": summary})
        if len(results) >= limit:
            break
    return results

# ---------- APKPure/APKMirror/Play (browser openers) ----------

def apkpure_search(query: str):
    url = f"https://apkpure.com/search?q={requests.utils.quote(query) if requests else query}"
    webbrowser.open(url)

def apkmirror_search(query: str):
    url = f"https://www.apkmirror.com/?post_type=app&s={requests.utils.quote(query) if requests else query}"
    webbrowser.open(url)

def play_search(query: str):
    url = f"https://play.google.com/store/search?q={requests.utils.quote(query) if requests else query}&c=apps"
    webbrowser.open(url)

def play_open_app(appid: str):
    url = f"https://play.google.com/store/apps/details?id={appid}"
    webbrowser.open(url)

# ---------- Android Device Ops (adb, aapt/apkanalyzer, apksigner) ----------

def aapt_bin() -> Optional[str]:
    return which("aapt") or which("aapt2")

def apkanalyzer_bin() -> Optional[str]:
    return which("apkanalyzer")

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
    aapt = aapt_bin()
    if aapt:
        code, out, err = run_cmd([aapt, "dump", "badging", str(apk)])
        if code != 0:
            return []
        perms = re.findall(r"uses-permission(?:-sdk-23)?:name='([^']+)'", out)
        return sorted(set(perms))
    # Fallback to apkanalyzer if available
    aka = apkanalyzer_bin()
    if aka:
        code, out, err = run_cmd([aka, "manifest", "permissions", str(apk)])
        if code != 0:
            return []
        perms = [p.strip() for p in out.splitlines() if p.strip()]
        return sorted(set(perms))
    return []

def aapt_dump_schemes(apk: Path) -> List[str]:
    aapt = aapt_bin()
    if aapt:
        code, out, err = run_cmd([aapt, "dump", "xmltree", str(apk), "AndroidManifest.xml"])
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
    return []

def aapt_dump_pkginfo(apk: Path) -> Dict[str, str]:
    # Extract packageName and versionCode/versionName
    aapt = aapt_bin()
    info = {"packageName": None, "versionCode": None, "versionName": None}
    if not aapt:
        return info
    code, out, err = run_cmd([aapt, "dump", "badging", str(apk)])
    if code != 0:
        return info
    m = re.search(r"package: name='([^']+)' versionCode='([^']+)' versionName='([^']*)'", out)
    if m:
        info["packageName"], info["versionCode"], info["versionName"] = m.group(1), m.group(2), m.group(3)
    return info

def apksigner_certs(apk: Path) -> str:
    apksigner = which("apksigner")
    if not apksigner:
        return "apksigner not found."
    code, out, err = run_cmd([apksigner, "verify", "--print-certs", str(apk)])
    return (out + "\n" + err).strip()

def android_device_version_code(pkg: str, device: Optional[str] = None) -> Optional[int]:
    # Parse dumpsys for versionCode
    cmd = ["adb"]
    if device:
        cmd += ["-s", device]
    cmd += ["shell", "dumpsys", "package", pkg]
    code, out, err = run_cmd(cmd)
    if code != 0:
        return None
    # Look for versionCode=NNN (long) or versionCode=NNN minSdk=...
    m = re.search(r"versionCode=(\d+)", out)
    if m:
        try:
            return int(m.group(1))
        except Exception:
            return None
    return None

def android_live_permission_analysis(pkg: str, device: Optional[str] = None) -> Dict[str, List[str]]:
    cmd = ["adb"]
    if device:
        cmd += ["-s", device]
    cmd += ["shell", "dumpsys", "package", pkg]
    code, out, err = run_cmd(cmd)
    if code != 0:
        raise click.ClickException(err.strip() or out or "dumpsys failed")
    requested = re.findall(r"android.permission.[A-Z0-9_.]+", out)
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
    if not which("security"):
        return {"note": "security tool not available to decode provisioning profile."}
    code, out, err = run_cmd(["security", "cms", "-D", "-i", str(prof)])
    if code != 0:
        return {"error": err or out}
    try:
        return plistlib.loads(out.encode("utf-8"))
    except Exception:
        try:
            return plistlib.loads(out.encode())
        except Exception:
            return {"raw": out}

def otool_macho_info(app_bundle: Path) -> str:
    if not which("otool"):
        return "otool not available."
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

# ---------- CLI Root ----------

@click.group()
@click.option("--verbose", is_flag=True, help="Enable debug logs.")
@click.pass_context
def cli(ctx, verbose):
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose

# ---------- Search ----------

@cli.group()
def search():
    """Search apps across sources."""
    pass

@search.command("fdroid")
@click.argument("query", nargs=-1, required=True)
@click.option("--limit", default=20, show_default=True)
@click.option("--offline", is_flag=True, help="Use offline F-Droid index cache.")
def search_fdroid(query, limit, offline):
    """Search F-Droid via API (or offline cache)."""
    q = " ".join(query)
    try:
        if offline:
            idx = fdroid_index_load()
            if not idx:
                raise click.ClickException("No offline cache. Run: bbt.py fdroid index-cache")
            results = fdroid_search_offline(idx, q, limit=limit)
        else:
            try:
                results = fdroid_search_api(q, limit=limit)
            except Exception:
                log("F-Droid API failed; trying offline cache...", "warn")
                idx = fdroid_index_load()
                if not idx:
                    raise
                results = fdroid_search_offline(idx, q, limit=limit)
    except Exception as e:
        raise click.ClickException(str(e))
    if not results:
        click.echo("No results.")
        return
    for app in results:
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
@click.option("--limit", default=10, show_default=True, help="Limit for F-Droid results.")
def search_all(query, limit):
    """Multi-source search: F-Droid in terminal; APKPure/APKMirror/Play in browser."""
    q = " ".join(query)
    try:
        res = []
        try:
            res = fdroid_search_api(q, limit=limit)
        except Exception:
            idx = fdroid_index_load()
            if idx:
                res = fdroid_search_offline(idx, q, limit=limit)
        click.echo("[F-Droid]")
        if not res:
            click.echo("  (no results)")
        for app in res:
            click.echo(f"  {app.get('packageName','?')} - {app.get('name','?')}")
    except Exception:
        click.echo("F-Droid lookup failed.")
    apkpure_search(q)
    apkmirror_search(q)
    play_search(q)
    click.echo("Opened APKPure, APKMirror, and Play in browser.")

# ---------- F-Droid Commands ----------

@cli.group()
def fdroid():
    """F-Droid specific actions (index cache, download, versions)."""
    pass

@fdroid.command("index-cache")
def fdroid_index_cmd():
    """Fetch and cache index-v2.json for offline search."""
    p = fdroid_index_cache_update()
    click.echo(f"Cached index at {p}")

@fdroid.command("versions")
@click.argument("appid")
def fdroid_versions(appid):
    """List published/suggested versions for an app."""
    info = fdroid_package_info(appid)
    click.echo(pretty_json(info))

@fdroid.command("download")
@click.argument("appid")
@click.option("--version-code", type=int, help="Specific versionCode to download. If omitted, uses suggestedVersionCode.")
@click.option("--out", type=click.Path(path_type=Path), default=Path("downloads"))
def fdroid_download(appid, version_code, out):
    """Directly download APK from F-Droid repo/archive and save to disk."""
    out.mkdir(parents=True, exist_ok=True)
    info = fdroid_package_info(appid)
    vcode = version_code or info.get("suggestedVersionCode")
    if not vcode:
        raise click.ClickException("Could not determine versionCode; specify --version-code.")
    apk_path = fdroid_try_download(appid, int(vcode), out)
    h = calc_hashes(apk_path)
    click.echo(f"Saved: {apk_path}")
    click.echo(f"SHA256: {h['sha256']}")

# ---------- Android Commands ----------

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
@click.option("--jobs", type=int, default=1, show_default=True, help="Parallel install jobs.")
def android_install_bulk(folder, device, jobs):
    apks = list(Path(folder).glob("*.apk"))
    if not apks:
        click.echo("No APKs in folder.")
        return
    def worker(apk):
        try:
            return apk.name, adb_install(apk, device=device)
        except Exception as e:
            return apk.name, f"Failed: {e}"
    if jobs <= 1:
        for i, apk in enumerate(apks, 1):
            click.echo(f"[{i}/{len(apks)}] Installing {apk.name} ...")
            name, res = worker(apk)
            click.echo(res)
    else:
        with ThreadPoolExecutor(max_workers=jobs) as ex:
            futs = {ex.submit(worker, apk): apk for apk in apks}
            for i, fut in enumerate(as_completed(futs), 1):
                name, res = fut.result()
                click.echo(f"[{i}/{len(apks)}] {name}: {res}")

@android.command("install-smart")
@click.argument("folder", type=click.Path(path_type=Path, exists=True))
@click.option("--device", help="Device serial.")
@click.option("--jobs", type=int, default=1, show_default=True)
def android_install_smart(folder, device, jobs):
    """
    Install only if APK versionCode > versionCode on device.
    Requires aapt or apkanalyzer for reading APK versionCode.
    """
    apks = list(Path(folder).glob("*.apk"))
    if not apks:
        click.echo("No APKs in folder.")
        return

    def should_install(apk: Path) -> Tuple[Path, bool, str]:
        info = aapt_dump_pkginfo(apk)
        pkg = info.get("packageName")
        vcode_apk = info.get("versionCode")
        if not pkg or not vcode_apk or not vcode_apk.isdigit():
            return apk, False, "Could not read APK package/versionCode (need aapt)."
        dev_vc = android_device_version_code(pkg, device=device)
        if dev_vc is None:
            return apk, True, f"{pkg} not installed on device; will install."
        if int(vcode_apk) > dev_vc:
            return apk, True, f"Newer versionCode {vcode_apk} > {dev_vc}; will install."
        return apk, False, f"Device has versionCode {dev_vc} >= {vcode_apk}; skipping."

    plan = [should_install(apk) for apk in apks]
    todo = [apk for (apk, do, _) in plan if do]
    for _, _, reason in plan:
        click.echo(reason)

    def worker(apk):
        try:
            return apk.name, adb_install(apk, device=device)
        except Exception as e:
            return apk.name, f"Failed: {e}"

    if not todo:
        click.echo("Nothing to install.")
        return
    if jobs <= 1:
        for i, apk in enumerate(todo, 1):
            click.echo(f"[{i}/{len(todo)}] Installing {apk.name} ...")
            name, res = worker(apk)
            click.echo(res)
    else:
        with ThreadPoolExecutor(max_workers=jobs) as ex:
            futs = {ex.submit(worker, apk): apk for apk in todo}
            for i, fut in enumerate(as_completed(futs), 1):
                name, res = fut.result()
                click.echo(f"[{i}/{len(todo)}] {name}: {res}")

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
@click.option("--jobs", type=int, default=4, show_default=True)
def android_backup_user(out, device, jobs):
    out.mkdir(parents=True, exist_ok=True)
    pkgs = adb_list_user_packages(device=device)
    if not pkgs:
        click.echo("No user apps found.")
        return
    def worker(pkg):
        path = adb_pkg_path(pkg, device=device)
        if not path:
            return pkg, False, "No path"
        dest = out / f"{pkg}.apk"
        ok = adb_pull(path, dest, device=device)
        return pkg, ok, str(dest) if ok else "pull failed"
    with ThreadPoolExecutor(max_workers=jobs) as ex:
        futs = [ex.submit(worker, p) for p in pkgs]
        for i, fut in enumerate(as_completed(futs), 1):
            pkg, ok, msg = fut.result()
            if ok:
                click.echo(f"[{i}/{len(pkgs)}] {pkg} -> {msg}")
            else:
                click.echo(f"[{i}/{len(pkgs)}] {pkg} failed: {msg}")

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
    info = aapt_dump_pkginfo(apk)
    perms = aapt_dump_permissions(apk)
    schemes = aapt_dump_schemes(apk)
    click.echo(pretty_json({"package": info, "permissions": perms, "url_schemes": schemes, "hashes": calc_hashes(apk)}))
    click.echo("\nCertificate info (apksigner):")
    click.echo(apksigner_certs(apk))

# ---------- iOS Commands ----------

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

# ---------- Cydia ----------

@cli.group()
def cydia():
    """Cydia/Sileo package discovery assistance (opens browser)."""
    pass

@cydia.command("search")
@click.argument("query", nargs=-1, required=True)
def cydia_search(query):
    q = " ".join(query)
    webbrowser.open(f"https://duckduckgo.com/?q=cydia+package+{q}")
    click.echo("Opened web search for Cydia packages in your browser.")

# ---------- Store ----------

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
    play_open_app(appid)
    click.echo("Browse the Similar section in your browser.")

@store.command("fdroid-history")
@click.argument("appid")
def store_fdroid_history(appid):
    info = fdroid_package_info(appid)
    click.echo(pretty_json(info))

# ---------- Utilities ----------

@cli.group()
def util():
    """Utility commands: hashes, certs, jsonfmt, base64, compare, cleanup."""
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

@util.command("compare-perms")
@click.argument("apk_old", type=click.Path(path_type=Path, exists=True))
@click.argument("apk_new", type=click.Path(path_type=Path, exists=True))
def util_compare_perms(apk_old, apk_new):
    """Compare requested permissions between two APKs."""
    old = set(aapt_dump_permissions(Path(apk_old)))
    new = set(aapt_dump_permissions(Path(apk_new)))
    added = sorted(new - old)
    removed = sorted(old - new)
    unchanged = sorted(old & new)
    click.echo(pretty_json({"added": added, "removed": removed, "unchanged": unchanged}))

@util.command("cleanup")
@click.argument("folder", type=click.Path(path_type=Path, exists=True))
@click.option("--days", type=int, default=30, show_default=True, help="Delete files older than N days.")
@click.option("--pattern", default="*.apk,*.ipa", show_default=True, help="Comma-separated glob patterns.")
@click.option("--yes", is_flag=True, help="Do not prompt for confirmation.")
def util_cleanup(folder, days, pattern, yes):
    """Delete old APK/IPA files by age and pattern."""
    folder = Path(folder)
    cutoff = datetime.now() - timedelta(days=days)
    patterns = [p.strip() for p in pattern.split(",") if p.strip()]
    targets = []
    for pat in patterns:
        for p in folder.rglob(pat):
            try:
                mtime = datetime.fromtimestamp(p.stat().st_mtime)
                if mtime < cutoff:
                    targets.append(p)
            except Exception:
                continue
    click.echo(f"Found {len(targets)} files older than {days} days.")
    if not targets:
        return
    if not yes:
        if not click.confirm("Delete these files?"):
            click.echo("Aborted.")
            return
    for p in targets:
        try:
            p.unlink()
            click.echo(f"Deleted {p}")
        except Exception as e:
            click.echo(f"Failed to delete {p}: {e}")

# ---------- Batch ----------

@cli.group()
def batch():
    """Batch operations over folders."""
    pass

@batch.command("analyze-apks")
@click.argument("folder", type=click.Path(path_type=Path, exists=True))
@click.option("--jobs", type=int, default=4, show_default=True)
def batch_analyze_apks(folder, jobs):
    folder = Path(folder)
    apks = list(folder.rglob("*.apk"))
    results = []
    def worker(apk: Path):
        perms = aapt_dump_permissions(apk)
        schemes = aapt_dump_schemes(apk)
        return {"apk": str(apk), "permissions": perms, "url_schemes": schemes, "hashes": calc_hashes(apk)}
    if jobs <= 1:
        for apk in apks:
            results.append(worker(apk))
    else:
        with ThreadPoolExecutor(max_workers=jobs) as ex:
            futs = [ex.submit(worker, a) for a in apks]
            for fut in as_completed(futs):
                results.append(fut.result())
    click.echo(pretty_json(results))

@batch.command("analyze-ipas")
@click.argument("folder", type=click.Path(path_type=Path, exists=True))
@click.option("--jobs", type=int, default=4, show_default=True)
def batch_analyze_ipas(folder, jobs):
    folder = Path(folder)
    ipas = list(folder.rglob("*.ipa"))
    def worker(ipa: Path):
        # Shallow analysis: just hashes for speed (deep analysis is expensive)
        return {"ipa": str(ipa), "hashes": calc_hashes(ipa)}
    results = []
    if jobs <= 1:
        for ipa in ipas:
            results.append(worker(ipa))
    else:
        with ThreadPoolExecutor(max_workers=jobs) as ex:
            futs = [ex.submit(worker, i) for i in ipas]
            for fut in as_completed(futs):
                results.append(fut.result())
    click.echo(pretty_json(results))

@batch.command("report")
@click.argument("folder", type=click.Path(path_type=Path, exists=True))
@click.option("--out", type=click.Path(path_type=Path), default=Path("app_inventory.json"))
@click.option("--open", "open_file", is_flag=True, help="Open the report after creation.")
def batch_report(folder, out, open_file):
    inv = build_inventory(Path(folder))
    with open(out, "w", encoding="utf-8") as f:
        json.dump(inv, f, ensure_ascii=False, indent=2)
    click.echo(f"Wrote report to {out}")
    if open_file:
        webbrowser.open(f"file://{Path(out).resolve()}")

if __name__ == "__main__":
    cli()