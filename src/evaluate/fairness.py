"""Compute Jain's fairness index from tcp_tool TOTAL lines."""

import sys


def main():
    path = sys.argv[1]
    totals = []
    for line in open(path, "r", errors="replace"):
        if not line.startswith("TOTAL "):
            continue
        fields = line.split()
        if len(fields) >= 3:
            totals.append((fields[1], int(fields[2])))
    if not totals:
        raise SystemExit("no TOTAL lines")
    values = [value for _, value in totals]
    count = len(values)
    total = sum(values)
    square = sum(value * value for value in values)
    index = (total * total) / (count * square) if square else 0.0
    for peer, value in totals:
        share = 100.0 * value / total if total else 0.0
        print("%s bytes=%d share=%.2f%%" % (peer, value, share))
    print("flows=%d total=%d Jain index=%.4f" % (count, total, index))


if __name__ == "__main__":
    main()
