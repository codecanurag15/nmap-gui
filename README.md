<div align="center">

```
███╗   ██╗███╗   ███╗ █████╗ ██████╗ 
████╗  ██║████╗ ████║██╔══██╗██╔══██╗
██╔██╗ ██║██╔████╔██║███████║██████╔╝
██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝ 
██║ ╚████║██║ ╚═╝ ██║██║  ██║██║     
╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     
```

### NmapGUI — every Nmap flag, one neon-lit window

![Platform](https://img.shields.io/badge/platform-Kali%20Linux-557C94?style=for-the-badge&logo=kalilinux&logoColor=white)
![Python](https://img.shields.io/badge/python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![GUI](https://img.shields.io/badge/GUI-PyQt5-41CD52?style=for-the-badge&logo=qt&logoColor=white)
![Engine](https://img.shields.io/badge/engine-Nmap-00E5FF?style=for-the-badge)

**A complete graphical front-end for Nmap.** Same flags, same scan modes, same output, with a live console, animated progress and reports you save only when you want them.

</div>

---

## ✨ Features

| | |
|---|---|
| 🎛️ **90+ Nmap options** | Every option sits in a tab, labelled with its real flag name (`-sS`, `-sV`, `-T4`, `--script`, `-D` ...) |
| 🧭 **All scan modes** | SYN, connect, ACK, Window, Maimon, Null, FIN, Xmas, SCTP, UDP, IP protocol, idle/zombie, FTP bounce |
| ⚡ **Ready-made profiles** | Zenmap-style presets: Intense, Quick, Ping, Slow comprehensive and more |
| 🔧 **Extra flags box** | Anything not in the tabs can be typed exactly as on the command line |
| 👁️ **Live command preview** | See the exact `nmap ...` command before you run it, and copy it |
| 📟 **Live colour console** | Open / closed / filtered ports, NSE output and scan reports are colour-coded as they stream in |
| 📊 **Real progress bar** | Driven by Nmap's own percentage and time-remaining, with the current phase shown |
| 🌐 **Results tree** | Hosts → ports → services, scripts, OS guesses and traceroute, with live stat cards |
| 💾 **Save on demand** | Nothing is written after a scan. Press **Save HTML report** when *you* want it |
| 🎨 **Animated UI** | Particle-network background, shimmering banner, spinning radar, glowing buttons, toasts |

---

## 🚀 Quick start

```bash
sudo apt update
sudo apt install nmap python3-pyqt5          # usually already on Kali

git clone https://github.com/codecanurag15/nmap-gui.git      # git clone tool repository 

cd nmap-gui
chmod +x run.sh
./run.sh                                      # starts the GUI as root
```

Prefer to launch it by hand?

```bash
sudo -E python3 nmap_gui.py
```

> **Why root?** SYN, UDP, OS-detection, ARP and raw-packet scans need raw sockets. Without root the GUI still works but shows a warning, and Nmap falls back to what it is allowed to do.

---

## 🕹️ How to use it

1. **Type a target** — hostname, IP, range or CIDR: `scanme.nmap.org`, `192.168.1.0/24`, `10.0.0.1-50`.
2. **Pick a profile** (optional) or tick options in the tabs on the left.
3. **Check the command** shown at the bottom. Add anything extra in *Extra flags*.
4. **Press Start scan** (or hit Enter in the target box). Watch the console and progress bar. **Stop** ends it at any time.
5. **Press Save HTML report** when you want to keep the results.

---

## 🗂️ Option tabs

| Tab | What's inside |
|---|---|
| **Target** | `-iL` `-iR` `--exclude` `--excludefile` `--randomize-hosts` `-6` |
| **Discovery** | `-sn` `-sL` `-Pn` `-PS` `-PA` `-PU` `-PY` `-PO` `-PE` `-PP` `-PM` `-PR` `-n` `-R` `--dns-servers` `--system-dns` `--traceroute` |
| **Scan** | TCP technique chips (`-sS` `-sT` `-sA` `-sW` `-sM` `-sN` `-sF` `-sX` `-sY` `-sZ`) plus `-sU` `-sO` `-sI` `-b` `--scanflags` |
| **Ports** | `-p` `-F` `--top-ports` `--port-ratio` `--exclude-ports` `-r` |
| **Service / OS** | `-sV` `--version-intensity` `--version-light` `--version-all` `--version-trace` `-O` `--osscan-limit` `--osscan-guess` `--max-os-tries` `-A` |
| **Scripts** | `-sC` `--script` (with category chips) `--script-args` `--script-args-file` `--script-trace` |
| **Timing** | `-T0` to `-T5`, parallelism, RTT timeouts, retries, scan delay, `--min-rate` `--max-rate`, rate-limit defeats |
| **Evasion** | `-f` `--mtu` `-D` `-S` `-e` `-g` `--proxies` `--data` `--data-string` `--data-length` `--ip-options` `--ttl` `--spoof-mac` `--badsum` |
| **Output / Misc** | `-v` `-d` `--reason` `--open` `--packet-trace` `--datadir` `--send-eth` `--send-ip` `--privileged` `--unprivileged` `--nsock-engine` |

The **Tools** menu also runs `-V`, `-h`, `--iflist`, `--script-updatedb` and `--script-help`.

### Profiles

`Intense scan` · `Intense scan + UDP` · `Intense scan, all TCP ports` · `Intense scan, no ping` · `Ping scan` · `Quick scan` · `Quick scan plus` · `Quick traceroute` · `Regular scan` · `Slow comprehensive scan`

---

## 📄 Reports

Scan reports are **never saved automatically**. After a scan finishes, three buttons light up:

| Button | Saves | Default location |
|---|---|---|
| **Save HTML report** | A styled, self-contained web page: summary cards, per-host port tables, scripts, OS guesses, traceroute and the raw output | `nmap-gui/reports/` |
| **Save .txt** | The console output with the command on top | `nmap-gui/reports/` |
| **Save .xml** | Nmap's native XML, for other tools | `nmap-gui/reports/` |

Files are named `nmap_YYYYMMDD_HHMMSS.<ext>`. A save dialog opens first, so you can rename the file or pick another folder.

> Running with `sudo` makes saved files root-owned. To take them back: `sudo chown -R $USER reports/`

---

## 📁 Project layout

```
nmap-gui/
├── nmap_gui.py     # the whole application
├── run.sh          # launcher (starts it as root)
├── README.md       # you are here
├── .gitignore      # keeps saved reports out of git
└── reports/        # saved scan reports go here
    └── .gitkeep
```

---

## 🛠️ Good to know

- **Progress:** the GUI adds `--stats-every 1s` to your scan so the bar can follow Nmap's progress. It is a hidden helper flag and is not shown in the command preview.
- **Structured data:** results and the HTML report are built from a temporary XML file that Nmap writes in the background. It is deleted when you start the next scan or close the app.
- **Stopped scans:** if you press Stop, the partial console output can still be saved.
- **Fonts:** it looks best with a code font such as Hack or JetBrains Mono: `sudo apt install fonts-hack fonts-jetbrains-mono`. It falls back to DejaVu automatically.

### Troubleshooting

| Problem | Fix |
|---|---|
| `No module named PyQt5` | `sudo apt install python3-pyqt5` |
| "Nmap not found" | `sudo apt install nmap` |
| GUI will not open under `sudo` | Use `sudo -E` (or `./run.sh`). If it still fails: `xhost +si:localuser:root` |
| Warning bar says "Not root" | Start it with `./run.sh` |

---

## ⚠️ Legal

Scan only systems you own or have **written permission** to test. Unauthorised scanning may be illegal. You are responsible for how you use this tool.

NmapGUI is an independent front-end. All scanning is done by [Nmap](https://nmap.org), created by Gordon "Fyodor" Lyon and the Nmap community.

<div align="center">

**Happy (authorised) scanning** 📡

</div>
