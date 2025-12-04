from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Dict, List, Any


# Titel für die Header Ausgabe
HEADERS_TITLE = "Verfügbare Header aus allen csv Dateien"


# Ordner und Pfade
_DATA_DIR = Path(__file__).resolve().parent / "sample-data"
_DESCRIPTION_PATH = _DATA_DIR / "description.json"

_DESCRIPTION_CACHE: str | None = None


def getDescription() -> str:
    """
    Gibt den kompletten JSON Text der description Datei zurück.
    """
    global _DESCRIPTION_CACHE
    if _DESCRIPTION_CACHE is None:
        _DESCRIPTION_CACHE = _DESCRIPTION_PATH.read_text(encoding="utf-8")
    return _DESCRIPTION_CACHE


def getDescriptionMarkdown() -> str:
    """
    Gibt die description.json als Markdown mit Erklärung zurück.
    """
    description_text = getDescription().strip()
    if not description_text:
        description_text = "{}"
    return (
        "## Beschreibung der Datenquelle\n"
        "Die Datei `description.json` enthält die textuellen Metadaten zu den CSV-Datensätzen.\n\n"
        "```json\n"
        f"{description_text}\n"
        "```"
    )


def _list_csv_files() -> List[Path]:
    """
    Interne Funktion die alle csv Dateien im sample Ordner liefert.
    """
    return sorted(_DATA_DIR.glob("*.csv"))


def getHeaders() -> str:
    """
    Gibt eine formatierte Ausgabe als Text zurück.
    Enthält den Titel plus eine Auflistung aller Dateien und ihren Spalten.
    """
    lines: List[str] = [HEADERS_TITLE, ""]

    for file in _list_csv_files():
        with file.open("r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader)
            cols = ", ".join(header)
            lines.append(f"{file.name}: {cols}")

    return "\n".join(lines)


def getHeadersMarkdown() -> str:
    """
    Gibt die Header-Übersicht inklusive Erklärung als Markdown zurück.
    """
    headers_text = getHeaders().strip()
    body = headers_text if headers_text else "Keine CSV-Dateien gefunden."
    return (
        f"## {HEADERS_TITLE}\n"
        "Jede Zeile beschreibt eine CSV-Datei gefolgt von ihren Spaltennamen in der ursprünglichen Reihenfolge.\n\n"
        "```\n"
        f"{body}\n"
        "```"
    )


def getSummary() -> Dict[str, Any]:
    """
    Liefert eine strukturierte Zusammensetzung aus:
    - Description JSON als dict
    - Header aller csv Dateien
    """
    try:
        description_json = json.loads(getDescription())
    except json.JSONDecodeError:
        description_json = {}

    headers_dict: Dict[str, List[str]] = {}
    for file in _list_csv_files():
        with file.open("r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader)
            headers_dict[file.name] = header

    return {
        "description": description_json,
        "headers": headers_dict,
    }


def getSummaryMarkdown() -> str:
    """
    Gibt die strukturierte Zusammenfassung als Markdown wieder.
    """
    summary = getSummary()
    description_json = summary.get("description", {})
    headers_dict = summary.get("headers", {})

    lines: List[str] = [
        "## Zusammenfassung aller Quelldaten",
        "Der Abschnitt `description` fasst den beschreibenden Inhalt der JSON-Datei zusammen, "
        "während `headers` für jede CSV-Datei die vorhandenen Spalten auflistet.",
        "### Description JSON",
    ]

    if description_json:
        pretty_description = json.dumps(description_json, indent=2, ensure_ascii=False)
        lines.extend(
            [
                "Die Metadaten stammen direkt aus `description.json`.",
                "```json",
                pretty_description,
                "```",
            ]
        )
    else:
        lines.append("Es lagen keine gültigen JSON-Metadaten vor.")

    lines.append("### CSV Header")
    if headers_dict:
        for file_name, columns in sorted(headers_dict.items()):
            joined_cols = ", ".join(columns)
            lines.append(f"- `{file_name}`: {joined_cols}")
    else:
        lines.append("Es wurden keine CSV-Header ermittelt.")

    return "\n\n".join(lines)



def getData(mode: str, percent: float, header: str, filename: str) -> List[Dict[str, Any]]:
    """
    Liefert aus der angegebenen csv Datei die Zeilen mit den
    höchsten oder niedrigsten Werten einer Spalte.

    mode    : "higher" oder "lower" (Groß Klein egal)
    percent : Prozentzahl der Datensätze die zurückgegeben werden sollen
    header  : Spaltenname auf den sich der Vergleich bezieht
    filename: Name der csv Datei innerhalb von sample data
    """
    mode_lc = mode.strip().lower()
    if mode_lc not in {"higher", "lower"}:
        raise ValueError('mode muss "higher" oder "lower" sein')

    csv_path = _DATA_DIR / filename
    if not csv_path.exists():
        raise FileNotFoundError(f"Datei nicht gefunden: {csv_path}")

    with csv_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if header not in (reader.fieldnames or []):
            raise ValueError(f"Spalte {header} nicht in Datei {filename}")

        rows = list(reader)

    # nur Zeilen mit numerischem Wert im gewünschten Header verwenden
    numeric_rows: List[Dict[str, Any]] = []
    for row in rows:
        value_str = row.get(header)
        if value_str is None:
            continue
        try:
            value_num = float(value_str)
        except ValueError:
            continue
        row["_value_num"] = value_num
        numeric_rows.append(row)

    if not numeric_rows:
        return []

    # sortieren nach dem numerischen Wert
    numeric_rows.sort(key=lambda r: r["_value_num"])

    # wie viele Datensätze sollen zurückkommen
    if percent <= 0:
        return []
    if percent > 100:
        percent = 100.0

    count = max(1, int(len(numeric_rows) * (percent / 100.0)))

    if mode_lc == "higher":
        selected = numeric_rows[-count:]
        selected.reverse()  # höchste zuerst
    else:  # "lower"
        selected = numeric_rows[:count]

    # Hilfswert wieder entfernen
    for row in selected:
        row.pop("_value_num", None)

    return selected


def _dicts_to_markdown_table(rows: List[Dict[str, Any]]) -> str:
    """
    Wandelt eine Liste aus Dictionaries in eine Markdown-Tabelle um.
    """
    if not rows:
        return ""

    columns: List[str] = []
    seen = set()
    for row in rows:
        for key in row.keys():
            if key not in seen:
                seen.add(key)
                columns.append(key)

    header_line = "| " + " | ".join(columns) + " |"
    separator_line = "| " + " | ".join("---" for _ in columns) + " |"
    body_lines: List[str] = []
    for row in rows:
        values = []
        for col in columns:
            value = row.get(col, "")
            if value is None:
                value = ""
            value_str = str(value).replace("|", r"\|").replace("\n", "<br>")
            values.append(value_str)
        body_lines.append("| " + " | ".join(values) + " |")
    return "\n".join([header_line, separator_line, *body_lines])


def getDataMarkdown(mode: str, percent: float, header: str, filename: str) -> str:
    """
    Liefert die getData-Ausgabe mit erläuterndem Markdown.
    """
    rows = getData(mode, percent, header, filename)
    percent_str = f"{percent:.2f}".rstrip("0").rstrip(".")
    intro = (
        f"## Datenauszug aus `{filename}`\n"
        f"Auswahlmodus: `{mode}`, Anteil: {percent_str}% basierend auf der Spalte `{header}`."
    )

    if not rows:
        return (
            f"{intro}\n\n"
            "Es konnten keine Zeilen mit numerischen Werten in der genannten Spalte ermittelt werden."
        )

    table = _dicts_to_markdown_table(rows)
    explanation = (
        "Die Tabelle enthält die gefilterten CSV-Zeilen. "
        "Jede Spalte entspricht den Originalfeldern der Datei, damit nachvollziehbar ist, "
        "welche Datensätze die höchsten oder niedrigsten Werte besitzen."
    )
    return f"{intro}\n\n{explanation}\n\n{table}"
