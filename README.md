# CR-18 / Module 7 — Capstone: Full Network Penetration Test

Sandbox definition for the CR-18 capstone. One engagement against a small
retail estate, chaining one technique from each earlier module and ending in a
report (delivered separately as the N7b assignment).

Set at Orion Retail Ltd, the company whose breach trainees reviewed in Module
6. The framing is the follow-up assessment: the board signed off a remediation
programme and wants independent confirmation that it landed. It did not.

## Topology

One flat office LAN, `192.168.60.0/24`. Segmentation is not what gates the
final objective — a host firewall is — which keeps the router doing nothing but
routing.

| Node | Image | IP | Role |
| ----- | ------------------- | ------------- | ---- |
| router | debian-12-x86_64 | 192.168.60.1 | LAN gateway. No filtering. Not a target. |
| vma | kali-2026.1-x86_64 | 192.168.60.10 | Assessment workstation. |
| web01 | ubuntu-noble-x86_64 | 192.168.60.20 | Operations panel on 80. HTTP Basic, no TLS. |
| fs01 | ubuntu-noble-x86_64 | 192.168.60.30 | Anonymous FTP drop, SSH, the transfer landing directory. |
| ws01 | ubuntu-noble-x86_64 | 192.168.60.40 | Office workstation. Runs the cleartext FTP transfer to fs01. |
| app01 | ubuntu-noble-x86_64 | 192.168.60.50 | Internal service on 8080. Answers ws01, refuses vma. |

`vma` runs on `c2_r4_d30` — Kali's image sets a 25 GiB `min_disk`, so
`standard.small` is not an option. The four Ubuntu hosts are `c1_r4_d20` and
the router is `standard.small`.

## Attack chain

Seven graded levels, one per module, and in every case the beginner or
intermediate variant of that module's technique rather than the advanced one.

| Level | Borrowed from | What the trainee does |
| ----- | ------------- | --------------------- |
| 3 | M2 | Sweep the scope, fingerprint services, read the asset tag out of the FTP greeting. Notes that app01 is up but filtered. |
| 4 | M6 | Recover the panel credential from the HTTP Basic session in the handover capture. |
| 5 | M6 → M4 | Use it against the panel. The panel names the transfer job and points at the fs01 drop. |
| 6 | M4 | Anonymous FTP yields the IT handover note and the staff directory. |
| 7 | M4 | Build a username list, attack SSH, land on the one account that was never rotated. |
| 8 | M3 | From that foothold, find the transfer schedule; ARP-poison ws01 ↔ fs01 and read the service credential off the wire. |
| 9 | M5 | The same credential is reused on ws01. SSH in, forward a port to app01, read the final flag. |

500 points over an estimated 150 minutes, which is the bottom of the
framework's `[150, 180]` band for N7a.

Nothing in the chain can be skipped:

- Level 7 needs the naming convention and the staff list from level 6.
- Level 8's credential is a hashed system password on both hosts. The
  plaintext exists on ws01, in a root-only file on a host the trainee has no
  access to yet. The wire is the only place it is readable.
- Level 9 is impossible from `vma` with any credential, because `app01` drops
  that source address outright. There is also no account on `app01`, so even
  from `ws01` there is no shell to get — the port forward is the only route.

## Provisioning

`provisioning/playbook.yml` runs seven plays: an apt-quieting play across the
five lab hosts, the same for the platform's `man` node, then one play per host.

Deliberate choices worth not undoing:

- **The router filters nothing.** `app01` carries the one access restriction as
  ufw with its default policy left at *allow*. A default-deny policy on a
  sandbox host cuts the platform's own management and console path and presents
  as "vm unreachable" rather than as a firewall.
- **SSH denial goes through PAM, not `DenyUsers`.** `pam_access.so` on the sshd
  stack only, so `svc_sync` can still authenticate to vsftpd, which has its own
  PAM stack. `DenyUsers` is not reliably honoured on these images.
- **`MaxStartups 100:30:200` on fs01.** The stock `10:30:100` silently drops
  hydra's parallel sessions, which reads to a trainee as "the password is not
  in the list".
- **The capture is checksum-gated.** A truncated or line-ending-mangled
  `orion-handover.pcapng` still copies cleanly and still leaves level 4 with no
  recoverable credential, so the vma play asserts its sha256 and fails loudly
  instead.
- **Flags are `0600` or `0444` and owned by the account that should hold them.**
  The panel source on web01 and the service source on app01 are `0600 root`:
  both embed a flag.

## Training definition

One, `training-n7a.json`, imported separately from this repo. Ten levels: a
briefing, the access level, seven graded steps and a closing summary.

Six of the seven answers come from APG variables in `variables.yml`, so no two
sandboxes share them. Level 4's answer is the static string
`Or10n_Rem3d1at3d!` and has to be: the capture is a fixed artefact, so the
password on the wire and the password the panel accepts must be the same
literal value.

`provisioning/files/make_capture.py` regenerates the capture. It has no
third-party dependencies — the pcapng and every frame, including the IP and TCP
checksums, are assembled by hand. Change the credential there and the panel
play's `panel_password` has to change with it, and the sha256 in the vma play
has to be updated.

## Accounts

| Host | Account | Credential | Purpose |
| ---- | ------- | ---------- | ------- |
| vma | `user` / `Password123` | — | Trainee console. |
| web01 | `webops` / `Or10n_Rem3d1at3d!` | Panel Basic auth | Recovered in level 4. |
| fs01 | `j.mercer` / `sunflower` | Weak, unrotated | Recovered in level 7. |
| fs01 | `a.hale`, `p.okonkwo`, `s.dubois`, `t.reyes` | Rotated, strong | Decoys. Denied over SSH by PAM. |
| fs01 | `svc_sync` | APG `sync_password` | FTP only, no shell. |
| ws01 | `svc_sync` | APG `sync_password` | Interactive. The reuse finding, and the level 9 foothold. |
| app01 | none | — | No account exists, by design. |

The candidate list deployed to `vma` is a single-word list of the shape the
handover note describes. rockyou is on the Kali image and would find the
password too, but a full run against a live sshd is not a good use of a
three-hour window.

## Tools used

`nmap`, `wireshark`/`tshark`, `curl`, `ftp`, `hydra`, `bettercap` or
`arpspoof`, `tcpdump`, `ssh`.

## MITRE mapping

| Tactic | Techniques |
| ------ | ---------- |
| Reconnaissance | T1595 Active Scanning |
| Initial Access | T1078 Valid Accounts, T1199 Trusted Relationship |
| Discovery | T1018, T1040, T1046, T1083, T1087 |
| Credential Access | T1040 Network Sniffing, T1110.001 Password Guessing, T1552 Unsecured Credentials, T1557.002 ARP Cache Poisoning |
| Lateral Movement | T1021.004 SSH |
| Collection | T1039 Data from Network Shared Drive |
| Command and Control | T1090 Proxy, T1572 Protocol Tunneling |
| Exfiltration | T1041 Exfiltration Over C2 Channel |

## Notes

The advanced variants of three modules are deliberately absent: N3c's NFQUEUE
packet rewriting, N5b's ligolo/NFS/`no_root_squash` chain, and N6b's IDS
evasion. Each is the hard version of a technique already represented here, and
any one of them would push this past three hours. The capstone is meant to be
the culmination of the course, not the hardest thing in it.

The report is a separate learning node (N7b) and is not part of this sandbox.
The seven findings the chain produces map one-to-one onto the sections that
assignment asks for.
