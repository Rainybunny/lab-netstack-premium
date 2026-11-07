"""Plot cwnd samples from NETSTACK_CC_LOG output as a standalone SVG."""

import sys


def parse(path):
    samples = []
    for line in open(path, "r", errors="replace"):
        if not line.startswith("CC "):
            continue
        fields = {}
        for item in line.split():
            if "=" in item:
                key, value = item.split("=", 1)
                fields[key] = value
        if "t" not in fields or "cwnd" not in fields:
            continue
        samples.append({
            "t": int(fields["t"]),
            "cwnd": int(fields["cwnd"]),
            "ssthresh": int(fields.get("ssthresh", 0)),
            "mode": int(fields.get("mode", 0)),
            "pacing": int(fields.get("pacing", 0)),
            "minrtt": int(fields.get("minrtt", 0)),
        })
    return samples


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: plot_cc.py CC_LOG OUTPUT.svg TITLE")
    samples = parse(sys.argv[1])
    output = sys.argv[2]
    title = sys.argv[3]
    if not samples:
        raise SystemExit("no CC samples")

    base = samples[0]["t"]
    points = [(sample["t"] - base, sample["cwnd"]) for sample in samples]
    duration = max(point[0] for point in points) or 1
    maximum = max(max(point[1] for point in points),
                  max(sample["ssthresh"] for sample in samples), 1)
    maximum = max(4 * 1460, maximum)
    width, height = 900, 360
    left, right, top, bottom = 70, 20, 40, 50
    plot_width = width - left - right
    plot_height = height - top - bottom

    def x(value):
        return left + value * plot_width / duration

    def y(value):
        return top + plot_height - value * plot_height / maximum

    lines = []
    lines.append('<?xml version="1.0" encoding="UTF-8"?>')
    lines.append('<svg xmlns="http://www.w3.org/2000/svg" width="%d" '
                 'height="%d" viewBox="0 0 %d %d">' %
                 (width, height, width, height))
    lines.append('<rect width="100%%" height="100%%" fill="white"/>')
    lines.append('<text x="%d" y="24" font-family="sans-serif" '
                 'font-size="16" text-anchor="middle">%s</text>' %
                 (width // 2, title))
    for tick in range(6):
        value = maximum * tick / 5
        py = y(value)
        lines.append('<line x1="%d" y1="%.1f" x2="%d" y2="%.1f" '
                     'stroke="#dddddd" stroke-width="1"/>' %
                     (left, py, width - right, py))
        lines.append('<text x="%d" y="%.1f" font-family="sans-serif" '
                     'font-size="11" text-anchor="end">%d</text>' %
                     (left - 8, py + 4, int(value)))
    for tick in range(6):
        value = duration * tick / 5
        px = x(value)
        lines.append('<text x="%.1f" y="%d" font-family="sans-serif" '
                     'font-size="11" text-anchor="middle">%.1f</text>' %
                     (px, height - bottom + 20, value / 1000.0))
    lines.append('<text x="%d" y="%d" font-family="sans-serif" '
                 'font-size="12" text-anchor="middle">time (s)</text>' %
                 (width // 2, height - 8))
    lines.append('<text x="16" y="%d" font-family="sans-serif" '
                 'font-size="12" text-anchor="middle" '
                 'transform="rotate(-90 16 %d)">cwnd (bytes)</text>' %
                 (top + plot_height // 2, top + plot_height // 2))

    cwnd_points = " ".join("%.1f,%.1f" % (x(t), y(c)) for t, c in points)
    lines.append('<polyline fill="none" stroke="#1f5fbf" stroke-width="2" '
                 'points="%s"/>' % cwnd_points)
    ssthresh_points = " ".join(
        "%.1f,%.1f" % (x(sample["t"] - base), y(sample["ssthresh"]))
        for sample in samples)
    lines.append('<polyline fill="none" stroke="#c04a1f" stroke-width="1" '
                 'stroke-dasharray="5,4" points="%s"/>' % ssthresh_points)

    previous_mode = samples[0]["mode"]
    for index, sample in enumerate(samples):
        if sample["mode"] != previous_mode:
            px = x(sample["t"] - base)
            lines.append('<line x1="%.1f" y1="%d" x2="%.1f" y2="%d" '
                         'stroke="#888888" stroke-width="1" '
                         'stroke-dasharray="2,3"/>' %
                         (px, top, px, top + plot_height))
            lines.append('<text x="%.1f" y="%d" font-family="sans-serif" '
                         'font-size="10">mode %d</text>' %
                         (px + 3, top + 12 + 12 * (index % 2),
                          sample["mode"]))
            previous_mode = sample["mode"]

    lines.append('<text x="%d" y="%d" font-family="sans-serif" '
                 'font-size="11" fill="#1f5fbf">cwnd</text>' %
                 (width - 160, top + 14))
    lines.append('<text x="%d" y="%d" font-family="sans-serif" '
                 'font-size="11" fill="#c04a1f">ssthresh</text>' %
                 (width - 160, top + 30))
    lines.append("</svg>")
    open(output, "w").write("\n".join(lines))

    decreases = 0
    for previous, current in zip(samples, samples[1:]):
        if current["cwnd"] + 1460 < previous["cwnd"]:
            decreases += 1
    modes = []
    for sample in samples:
        if not modes or modes[-1] != sample["mode"]:
            modes.append(sample["mode"])
    print("samples=%d duration=%.2fs cwnd min=%d max=%d decreases=%d" %
          (len(samples), duration / 1000.0,
           min(sample["cwnd"] for sample in samples), maximum, decreases))
    print("mode sequence: %s" % " -> ".join(str(mode) for mode in modes))
    print("final pacing rate: %d bytes/s, min RTT: %d ms" %
          (samples[-1]["pacing"], samples[-1]["minrtt"]))
    print("plot written to %s" % output)


if __name__ == "__main__":
    main()
