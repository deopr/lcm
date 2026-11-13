"""First-boot validation for a freshly replaced system.

Runs inside the target, after it has booted.  Writes a machine-readable
report and a small key=value file that `lcm commit` consumes.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from lcm.util import Style, run_ok, utc_now, write_json

REPORT_JSON = Path("/var/lib/lcm/validation.json")
REPORT_ENV = Path("/var/lib/lcm/validation.env")


@dataclass
class Check:
    name: str
    ok: bool
    detail: str

    def to_dict(self) -> dict:
        return dict(self.__dict__)


def _root_subvol() -> str | None:
    ok, out, _ = run_ok(["findmnt", "-no", "OPTIONS", "/"])
    if not ok:
        return None
    match = re.search(r"(?:^|,)subvol=/?([^,]+)", out)
    return match.group(1) if match else None


def _failed_units() -> tuple[int, list[str]]:
    ok, out, _ = run_ok(["systemctl", "--failed", "--no-legend"])
    if not ok:
        return -1, []
    lines = [line for line in out.splitlines() if line.strip()]
    names = [line.split()[0] for line in lines if line.split()]
    return len(lines), names


def _default_route() -> bool:
    ok, out, _ = run_ok(["ip", "route", "show", "default"])
    return ok and bool(out.strip())


def _gpu() -> tuple[bool, str]:
    drm = Path("/dev/dri")
    if not drm.is_dir():
        return False, "no /dev/dri"
    cards = sorted(path.name for path in drm.iterdir())
    return bool(cards), ", ".join(cards) or "empty"


def _audio() -> tuple[bool, str]:
    ok, out, _ = run_ok(["wpctl", "status"])
    if ok:
        has_sink = "Sink" in out or "Audio/Sink" in out
        return has_sink, "wpctl sink present" if has_sink else "wpctl: no sink"
    ok, out, _ = run_ok(["pactl", "info"])
    if ok:
        return True, "pulse/pactl reachable"
    return True, "no audio tooling found (skipped)"


def _display_manager() -> tuple[bool, str]:
    ok, out, _ = run_ok(["systemctl", "is-active", "display-manager"])
    if ok and out.strip() == "active":
        return True, "display-manager active"
    for unit in ("gdm", "sddm", "lightdm", "greetd", "cosmic-greeter"):
        ok, out, _ = run_ok(["systemctl", "is-active", unit])
        if ok and out.strip() == "active":
            return True, f"{unit} active"
    return False, "no display manager active"


def _firmware_errors() -> tuple[bool, str]:
    ok, out, _ = run_ok(["dmesg", "--level=err,warn"])
    if not ok:
        return True, "dmesg unavailable (skipped)"
    hits = [
        line
        for line in out.splitlines()
        if "firmware" in line.lower() and ("fail" in line.lower() or "error" in line.lower())
    ]
    return not hits, f"{len(hits)} firmware errors" if hits else "none"


def collect(
    *,
    expected_subvol: str | None = None,
    max_failed_units: int = 0,
) -> dict:
    checks: list[Check] = []

    subvol = _root_subvol()
    if expected_subvol:
        checks.append(
            Check(
                "root_subvolume",
                subvol == expected_subvol,
                f"running from {subvol or '?'} (expected {expected_subvol})",
            )
        )
    else:
        checks.append(Check("root_subvolume", bool(subvol), f"subvol={subvol or '?'}"))

    failed, names = _failed_units()
    checks.append(
        Check(
            "failed_units",
            failed <= max_failed_units if failed >= 0 else False,
            f"{failed} failed unit(s)" + (": " + ", ".join(names[:8]) if names else ""),
        )
    )

    checks.append(Check("network", _default_route(), "default route present" if _default_route() else "no default route"))

    gpu_ok, gpu_detail = _gpu()
    checks.append(Check("gpu", gpu_ok, gpu_detail))

    audio_ok, audio_detail = _audio()
    checks.append(Check("audio", audio_ok, audio_detail))

    dm_ok, dm_detail = _display_manager()
    checks.append(Check("display_manager", dm_ok, dm_detail))

    home = Path.home()
    checks.append(
        Check("home", home.is_dir() and os.access(home, os.W_OK), f"{home}")
    )

    fw_ok, fw_detail = _firmware_errors()
    checks.append(Check("firmware", fw_ok, fw_detail))

    return {
        "ok": all(check.ok for check in checks),
        "checks": [check.to_dict() for check in checks],
        "subvol": subvol,
        "kernel": os.uname().release,
        "time": utc_now(),
    }


def write(report: dict, esp_mount: str | None = None) -> None:
    try:
        REPORT_JSON.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        return
    write_json(REPORT_JSON, report, mode=0o644)

    by_name = {check["name"]: check for check in report["checks"]}
    lines = [
        f"ok={1 if report['ok'] else 0}",
        f"failed_units={0 if by_name.get('failed_units', {}).get('ok') else 1}",
        f"root_subvol={1 if by_name.get('root_subvolume', {}).get('ok') else 0}",
        f"network={1 if by_name.get('network', {}).get('ok') else 0}",
        f"gpu={1 if by_name.get('gpu', {}).get('ok') else 0}",
        f"audio={1 if by_name.get('audio', {}).get('ok') else 0}",
        f"display_manager={1 if by_name.get('display_manager', {}).get('ok') else 0}",
        f"kernel={report.get('kernel', '')}",
    ]
    try:
        REPORT_ENV.write_text("\n".join(lines) + "\n", encoding="utf-8")
        if esp_mount:
            Path(esp_mount, "lcm-validation.env").write_text(
                "\n".join(lines) + "\n", encoding="utf-8"
            )
    except OSError:
        pass


def render(report: dict, style: Style | None = None) -> str:
    style = style or Style(False)
    lines = [style.bold("LCM validation")]
    for check in report["checks"]:
        mark = style.green("ok  ") if check["ok"] else style.red("FAIL")
        lines.append(f"  [{mark}] {check['name']:<16} {check['detail']}")
    lines.append("")
    if report["ok"]:
        lines.append(style.green("All checks passed. Run `sudo lcm commit` to finish."))
    else:
        lines.append(
            style.yellow(
                "Some checks failed. The old system is still bootable: "
                "run `sudo lcm rollback` or select it in the firmware menu."
            )
        )
    return "\n".join(lines)
