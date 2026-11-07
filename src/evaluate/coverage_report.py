"""Turn gcov .gcov files into a small HTML coverage report."""

import os
import sys


def parse_gcov(path):
    source = None
    executable = 0
    covered = 0
    uncovered = []
    for line in open(path, "r", errors="replace"):
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        count_text = parts[0].strip()
        line_number = parts[1].strip()
        code = parts[2].rstrip("\n")
        if line_number == "0" and code.startswith("Source:"):
            source = code[len("Source:"):]
            continue
        if count_text == "-" or not line_number.isdigit():
            continue
        executable += 1
        if count_text in ("#####", "=====") or count_text == "0":
            uncovered.append((int(line_number), code.strip()))
        else:
            covered += 1
    return source, executable, covered, uncovered


def main():
    output_dir = sys.argv[1]
    gcov_dir = sys.argv[2]
    rows = []
    for name in sorted(os.listdir(gcov_dir)):
        if not name.endswith(".gcov"):
            continue
        source, executable, covered, uncovered = parse_gcov(
            os.path.join(gcov_dir, name))
        if source is None or executable == 0:
            continue
        normalized = source.replace("\\", "/")
        if "/src/" not in normalized or (
                not normalized.endswith(".cpp") and
                not normalized.endswith(".h")):
            continue
        if normalized.startswith("/usr/"):
            continue
        display = "src/" + normalized.split("/src/", 1)[1]
        rows.append({
            "file": display,
            "executable": executable,
            "covered": covered,
            "percent": 100.0 * covered / executable,
            "uncovered": uncovered,
        })
    rows.sort(key=lambda row: row["file"])
    total_executable = sum(row["executable"] for row in rows)
    total_covered = sum(row["covered"] for row in rows)
    total_percent = (100.0 * total_covered / total_executable
                     if total_executable else 0.0)

    for row in rows:
        print("%-32s %6d %6d %6.2f%%" %
              (row["file"], row["covered"], row["executable"],
               row["percent"]))
    print("%-32s %6d %6d %6.2f%%" %
          ("TOTAL", total_covered, total_executable, total_percent))

    html = [
        "<!doctype html><html><head><meta charset=\"utf-8\">",
        "<title>Lab 3 coverage</title>",
        "<style>body{font-family:sans-serif;margin:24px}"
        "table{border-collapse:collapse;margin-bottom:24px}"
        "th,td{border:1px solid #bbb;padding:4px 10px;text-align:right}"
        "th:first-child,td:first-child{text-align:left}"
        "code{font-family:monospace}</style></head><body>",
        "<h1>Lab 3 gcov line coverage</h1>",
        "<p>Unit tests: <code>build/coverage/unit_tests</code>.</p>",
        "<table><tr><th>File</th><th>Covered</th><th>Executable</th>"
        "<th>Line coverage</th></tr>",
    ]
    for row in rows:
        html.append("<tr><td>%s</td><td>%d</td><td>%d</td>"
                    "<td>%.2f%%</td></tr>" %
                    (row["file"], row["covered"], row["executable"],
                     row["percent"]))
    html.append("<tr><td><b>TOTAL</b></td><td><b>%d</b></td>"
                "<td><b>%d</b></td><td><b>%.2f%%</b></td></tr>" %
                (total_covered, total_executable, total_percent))
    html.append("</table>")
    html.append("<h2>Uncovered lines</h2>")
    for row in rows:
        if not row["uncovered"]:
            continue
        html.append("<h3>%s</h3><ul>" % row["file"])
        for line_number, code in row["uncovered"][:80]:
            html.append("<li><code>%d</code>: %s</li>" %
                        (line_number, code.replace("<", "&lt;")
                         .replace(">", "&gt;")))
        html.append("</ul>")
    html.append("</body></html>")
    output = os.path.join(output_dir, "cl10-coverage.html")
    open(output, "w").write("\n".join(html))
    print("HTML report written to %s" % output)


if __name__ == "__main__":
    main()
