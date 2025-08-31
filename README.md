# Zeka: The Zero-Knowledge Argument<sup>*</sup> Engine

Zeka is a cross-platform scoring engine for "find-and-fix" cybersecurity exercises, featuring a novel cryptographic scheme that ensures competition integrity and ease of use.

[LDOV.pdf](/technical/LDOV.pdf) contains a brief explanation of the Lagrange-DFA offline verification scheme, the atom upon which this engine is built. A (slightly more accessible) blog article is in writing!

NOTE: Zeka currently only implements event providers for Linux. Event providers for Windows are on their way and will likely be released next year.

<sup>*</sup>the "zero-knowledge argument" phrasing in the name should be understood only in a heuristic sense. In its intended scoring engine use, the scheme reveals no information other than whether a vulnerability was scored correctly. I do not claim that the construction satisfies the formal cryptographic definition of a zero-knowledge argument or proof.

# Usage
```
# Generate a zeka.dat from a YAML config.
./zeka_config -c /path/to/config.yaml

# Run the engine. A report.html will be generated automatically in the current directory.
sudo ./zeka_engine
``` 

# Configuration

Zeka uses YAML as the schema for its domain-specific language. The config forces you to denote categories to make you more conscious of the distribution of vulnerabilities within your image and to ensure a uniform score report ordering. Zeka always orders categories in the order listed below, and it sorts vulnerabilities lexicographically within each category.

```yaml
- title: <string>                       # The title to be displayed on the score report (default: "Training Round").
- seed: <integer>                       # The seed for generating zeka.dat (default: <system time>).
- aead: <string>                        # The additional data to authenticate with AES-GCM (default: <none>).
- remote_url: <url>                     # NOT IMPLEMENTED: The Sarpedon endpoint to send scores to.
- remote_password: <string>             # NOT IMPLEMENTED: The password to encrypt scoring updates to Sarpedon.
- is_local: <bool>                      # NOT IMPLEMENTED: Whether the engine scores offline
---                                     # These triple dashes are required.

# DSL overview:
# - &<yaml_var> <string>

# - <vuln_message>: <integer|float>
#   category: <string>
#   pass:
#     <[<conditions>]: [or|and|<check_type>]>
#     <or: [<conditions>]>
#     <and: [<conditions>]>
#     <<check_type>: [<args>]>

# Valid categories: [
#     "fq",
#     "user_auditing",
#     "account_policy",
#     "local_policy",
#     "defensive_countermeasure",
#     "uncategorized",
#     "service_auditing",
#     "os_update",
#     "app_update",
#     "prohibited_file",
#     "unwanted_software",
#     "malware",
#     "appsec",
# ]

- &fq1 /path/to/fq1
- &fq2 /path/to/fq1

- Forensics Question 1 Correct: 5
  category: fq
  pass:
    # (regex(*fq1, "fq1: A") & regex(*fq1, "fq1: B")) | regex(*fq1, "fq1: 2")
    - or:
      - and:
        - regex: [*fq1, "fq1: A"]       # *fq1 is substituted with its value defined above: `/path/to/fq1`
        - regex: [*fq1*, "fq1: B"]
      - regex: [*fq1, "fq1: 2"]

- Forensics Question 2 Correct: 5
  category: fq
  pass:
    # Implicit AND if no AND or OR is listed
    # regex(*fq2, "fq2: 1") & regex(*fq2, "fq2: 2") & regex(*fq2, "fq2: 3")
    - regex: [*fq2, "fq2: 1"]
    - regex: [*fq2, "fq2: 2"]
    - regex: [*fq2, "fq2: 3"]
```

# Example Scoring Report
![report](/assets/report.png)

# Building
## On Windows
NOTE: The first build of the `gmp-mpfr-sys` crate might take a LONG time (as long as 10-15 minutes)!

### For Windows:
1. Install [Rust](https://www.rust-lang.org/tools/install) outside WSL.
2. Install [MSYS2](https://www.msys2.org/).
	- If you run into permissions errors, download the self-extracting archive version and run `.\msys2-base-x86_64-latest.sfx.exe -y -oC:\`.
3. Open MinGW64.
	- This is likely `C:\msys64\clang64.exe`.
4. Install the requisite build tools within MinGW.
	- `pacman -S pacman-mirrors`
	- `pacman -S diffutils m4 make mingw-w64-x86_64-clang`
5. Add `clang` and `cargo` to PATH. 
	- `PATH=$PATH:/mingw64/bin:/c/users/<your username>/.cargo/bin`
6. Build.
	- `CC=clang cargo build`

NOTE: Whenever you run a `cargo` command (e.g. `cargo run`), run it in MinGW64 and prefix it with `CC=clang` (e.g. `CC=clang cargo run`).
 
### For Linux:
1. Install [Rust](https://www.rust-lang.org/tools/install) inside WSL.
	- NOTE: For performance reasons, you may want to clone this repo to a non-mounted path (e.g. to `~/ZekaEngine` instead of `/mnt/c/users/<your username>/desktop/ZekaEngine`).
2. Install the requisite build tools.
	- `sudo apt-get install m4`
3. Build.
	- `cargo build`

## On Linux

### For Windows
TBD

### For Linux
1. Install [Rust](https://www.rust-lang.org/tools/install).
2. Install the requisite build tools.
	- `sudo apt-get install m4`
3. Build.
	- `cargo build`

---

[alex@ajiang.xyz](mailto:alex@ajiang.xyz). Discord: @syossu