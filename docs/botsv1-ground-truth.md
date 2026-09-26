# BOTS v1 Ground Truth — What Was Actually Malicious

Dataset: [Splunk Boss of the SOC v1](https://github.com/splunk/botsv1) — real
instrumented logs from Wayne Enterprises, August 2016. Two independent attacks
are buried in the noise. The pipeline sees **no hints**: this document is the
scoring key, compiled from public answer walkthroughs
([samsclass](https://samsclass.info/50/proj/botsv1.htm),
[andickinson](https://andickinson.github.io/blog/splunk-boss-of-the-soc-v1/),
[CyberDefenders](https://cyberdefenders.org/walkthroughs/boss-of-the-soc-v1/)).

## Attack 1 — "P01s0n1vy" APT: web defacement

External group defaces the company website `imreallynotbatman.com`
(Joomla CMS, web server `192.168.250.70`).

| Stage | Ground truth |
|---|---|
| Recon | `40.80.148.42` scans the web server with **Acunetix** |
| Brute force | `23.22.63.114` brute-forces the Joomla `admin` account — **412** unique passwords; first attempt `12345678`; success with **`batman`** |
| Payload | uploads executable **`3791.exe`** (MD5 `AAE3F5A29935E6ABCC2C2754D12A9AF0`) |
| Defacement | drops **`poisonivy-is-coming-for-you-batman.jpeg`** on the site |
| C2 / staging | `23.22.63.114` again; dynamic-DNS FQDN **`prankglassinebracket.jumpingcrab.com`**; group email `lilian.rose@po1s0n1vy.com` |

## Attack 2 — Cerber ransomware: insider USB infection

Employee **Bob Smith** (workstation **`we8105desk`**, `192.168.250.100` on
2016-08-24) plugs in a USB key named **`MIRANDA_PRI`** and executes malware.
Encryption spreads to the file server `192.168.250.20`.

| Stage | Ground truth |
|---|---|
| Initial execution | macro doc **`miranda_tate_unveiled.dotm`** |
| Script stage | heavily obfuscated VBScript (CommandLine ~4,490 chars) spawns **`121214.tmp`** |
| Cryptor download | **`mhtr.jpg`** (actually Cerber code) from first suspicious domain **`solidaritedeproximite.org`** |
| Ransom note C2 | **`cerberhhyed5frqa.xmfir0.win`** |
| Impact | 406 .txt files encrypted in Bob's profile, 257 PDFs on the file server; Suricata Cerber SID `2816763` |

## What a good detection looks like

- **System 1** should escalate: Acunetix scan traffic, the 412-password brute
  force, `3791.exe` upload/execution, `miranda_tate_unveiled.dotm`,
  the 4,490-char VBScript, `121214.tmp`, `mhtr.jpg` download, Cerber domains.
- **System 2** should cluster escalations into campaigns anchored on
  `192.168.250.70` / `we8105desk` with tactics spanning
  recon → credential-access → execution → impact, and its narratives should
  name the artifacts above.
