import os, sys, re, argparse, json
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor  # <-- मल्टी-प्रोसेसिंग के लिए जोड़ा गया

RESET   = "\033[0m"
BOLD    = "\033[1m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
MAGENTA = "\033[95m"
DIM     = "\033[2m"

def colorize(text, *codes):
    return "".join(codes) + text + RESET

WELCOME_CAT = r"""
       _..---...,""-._     ,/}/)
    .''        ,      ``..'(/-<       
   /   _      {      )         \
  ;   _ `.     `.   <         O(        I'm very cute!
,'   ( \  )      `.  \ __.._ .: y
(  <\_-) )'-.____...\  `._   //-'
 `. `-' /-._)))      `-._)))
 
              HISSLOCK CLI
         [ STATIC SAST SCANNER ]  
"""

ANGRY_CAT = r"""
       _..---...,""-._     ,/}/)
    .''        ,      ``..'(/-<
   /   _      {      )         \
  ;   _ `.     `.   <         O(             ANGRY CAT!
,'   ( \  )      `.  \ __.._ .: y
(  <\_-) )'-.____...\  `._   //-'
 `. `-' /-._)))      `-._)))
       
  I scan code faster than SpaceX rockets,
  Because I am Elon Musk's favorite cat!
"""

RULES = [
    {
        "name": "AWS Access Key ID",
        "pattern": re.compile(r"AKIA[A-Z0-9]{16}"),
        "severity": "HIGH",
        "tip": "Rotate this key immediately and use environment variables or IAM roles.",
    },
    {
        "name": "OpenAI API Key",
        "pattern": re.compile(r"sk-proj-[a-zA-Z0-9_\-]{50,255}"),
        "severity": "HIGH",
        "tip": "OpenAI Project API Key exposed! Revoke it instantly from the OpenAI Developer Dashboard.",
    },
    {
        "name": "AWS Secret Access Key",
        "pattern": re.compile(r'(?i)(?:aws_secret_access_key|aws_secret)[^=:]*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'),
        "severity": "HIGH",
        "tip": "Never commit AWS secrets. Use ~/.aws/credentials or Secrets Manager.",
    },
    {
        "name": "Google API Key",
        "pattern": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "severity": "HIGH",
        "tip": "Restrict this key in Google Cloud Console and move it to env vars.",
    },
    {
        "name": "GitHub Token",
        "pattern": re.compile(r"(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})"),
        "severity": "HIGH",
        "tip": "Revoke this token on GitHub immediately and rotate secrets.",
    },
    {
        "name": "Stripe Secret Key",
        "pattern": re.compile(r"sk_live_[0-9a-zA-Z]{24,60}"),
        "severity": "HIGH",
        "tip": "Stripe keys can lead to financial loss. Revoke immediately and use env vars.",
    },
    {
        "name": "Slack Bot/User Token",
        "pattern": re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,40}-[a-zA-Z0-9\-]+"),
        "severity": "HIGH",
        "tip": "Slack tokens expose internal communications. Revoke and use a secrets vault.",
    },
    {
        "name": "Discord Webhook URL",
        "pattern": re.compile(r'(?i)https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[a-zA-Z0-9_\-]+'),
        "severity": "HIGH",
        "tip": "Exposed Discord webhooks can be abused for spam. Delete it and use env vars.",
    },
    {
        "name": "RSA/OpenSSH Private Key Block",
        "pattern": re.compile(r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP|PRIVATE) KEY-----"),
        "severity": "HIGH",
        "tip": "Never hardcode private key blocks. Store them securely in a key manager.",
    },
    {
        "name": "Hardcoded JWT (JSON Web Token)",
        "pattern": re.compile(r"eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]+"),
        "severity": "MEDIUM",
        "tip": "Hardcoded JWTs can lead to impersonation. Generate tokens dynamically.",
    },
    {
        "name": "Twilio API Key",
        "pattern": re.compile(r"SK[0-9a-fA-F]{32}"),
        "severity": "HIGH",
        "tip": "Revoke Twilio key to prevent unauthorized SMS/calls and billing fraud.",
    },
    {
        "name": "Mailgun API Key",
        "pattern": re.compile(r"key-[0-9a-zA-Z]{32}"),
        "severity": "HIGH",
        "tip": "Rotate Mailgun key to protect your email sending reputation.",
    },
    {
        "name": "SendGrid API Key",
        "pattern": re.compile(r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}"),
        "severity": "HIGH",
        "tip": "Revoke SendGrid key immediately. Malicious actors can send spam on your behalf.",
    },
    {
        "name": "Square Access Token",
        "pattern": re.compile(r"sq0atp-[0-9A-Za-z\-_]{22}"),
        "severity": "HIGH",
        "tip": "Revoke Square token to prevent unauthorized point-of-sale transactions.",
    },
    {
        "name": "Database URI with Password",
        "pattern": re.compile(r"(?:postgres|mysql|mongodb(?:\+srv)?|redis)://[^:]+:[^@]+@[^/\s]+"),
        "severity": "HIGH",
        "tip": "Do not hardcode database credentials. Use a secure vault or env variables.",
    },
    {
        "name": "Azure Storage Account Key",
        "pattern": re.compile(r'(?i)AccountKey=[A-Za-z0-9+/=]{88}'),
        "severity": "HIGH",
        "tip": "Rotate Azure Storage keys immediately to protect cloud data.",
    },
    {
        "name": "Use of eval()", 
        "pattern": re.compile(r"eval\s*\("),
        "severity": "HIGH",
        "tip": "Replace eval() with ast.literal_eval() or a safer alternative.", 
    },
    {
        "name": "Use of exec()", 
        "pattern": re.compile(r"exec\s*\("),
        "severity": "HIGH",
        "tip": "Avoid exec(). Refactor to explicit function calls.", 
    },
    {
        "name": "subprocess shell=True", 
        "pattern": re.compile(r"subprocess\.[a-zA-Z_0-9]+\([^)]*shell\s*=\s*True", re.IGNORECASE),
        "severity": "MEDIUM",
        "tip": "Pass a list of args instead and remove shell=True to prevent injection.",
    },
    {
        "name": "os.system() call", 
        "pattern": re.compile(r"os\.system\s*\("),
        "severity": "MEDIUM",
        "tip": "Use subprocess.run() with a list of arguments instead.",
    },
    {
        "name": "Pickle deserialisation",
        "pattern": re.compile(r"pickle\.(?:loads?|Unpickler)\s*\("),
        "severity": "MEDIUM",
        "tip": "Never unpickle data from untrusted sources. Use JSON or protobuf.",
    },
    {
        "name": "Weak Hash Algorithm (MD5/SHA1)",
        "pattern": re.compile(r"hashlib\.(?:md5|sha1)\s*\("),
        "severity": "MEDIUM",
        "tip": "Use SHA-256 or stronger for security-sensitive hashing.",
    },
    {
        "name": "SSL Certificate Verification Disabled",
        "pattern": re.compile(r"verify\s*=\s*False", re.IGNORECASE),
        "severity": "HIGH",
        "tip": "Never disable SSL verification in production. This exposes network calls to MITM attacks.",
    },
    {
        "name": "Insecure FTP Protocol Usage",
        "pattern": re.compile(r"from\s+ftplib\s+import|ftplib\.FTP"),
        "severity": "MEDIUM",
        "tip": "FTP transmits data in cleartext. Use SFTP (paramiko) or HTTPS instead."
    },
    {
        "name": "Binding to 0.0.0.0",
        "pattern": re.compile(r'(["\'])0\.0\.0\.0\1'),
        "severity": "LOW",
        "tip": "Bind only to the required interface (e.g. 127.0.0.1) in production.",
    },
    {
        "name": "Debug Mode Enabled",
        "pattern": re.compile(r"(?i)(?:debug|DEBUG)[^=:]*[:=]\s*True"),
        "severity": "LOW",
        "tip": "Disable debug mode before deploying to production.",
    },
    {
        "name": "Assert Used for Security Validation",
        "pattern": re.compile(r"assert\s+.*(?:admin|permission|auth|role|login)"),
        "severity": "LOW",
        "tip": "Assert statements can be removed during Python optimization (-O). Use if-statements for security checks."
    },
    {
        "name": "Hardcoded Localhost / Internal Domain",
        "pattern": re.compile(r'(?i)(["\'])https?://(?:localhost|127\.0\.0\.1|test\.local)[^"\']*?\1'),
        "severity": "LOW",
        "tip": "Localhost/Testing URL hardcoded. Ensure these are managed via configuration files."
    },
    {
        "name": "Private Enterprise API Key",
        "pattern": re.compile(r"sk_priv_[A-Za-z0-9]{32,}"),
        "severity": "HIGH",
        "tip": "Revoke and regenerate this private key. Store it in a secrets manager.",
    },
    {
        "name": "Authorization Bearer Token", 
        "pattern":re.compile(r'(?i)(?:["\']?Authorization["\']?\s*[:=]\s*)?["\']?Bearer\s+[A-Za-z0-9\-._~+/]+=*'),
        "severity": "HIGH",
        "tip": "Never hardcode Bearer tokens. Inject them at runtime via env or vault.", 
    },
    {
        "name": "X-API-Key / X-Private-Token Header",
        "pattern": re.compile(r'(?i)(?:X-API-Key|X-Private-Token)["\']?\s*[:=]\s*(["\'])([A-Za-z0-9\-_]{16,})\1'),
        "severity": "HIGH",
        "tip": "Rotate this header secret and load it from environment variables.",
    },
    {
        "name": "Private/Internal API Endpoint",
        "pattern": re.compile(r'(?i)(?:https?://)?[\w\-]+(?:\.internal|\.local)(?:/[\w\-/]*)?|internal[\-_]api/v\d+'),
        "severity": "HIGH",
        "tip": "Internal endpoints must never be hardcoded. Use config/env vars.",
    },
    {
        "name": "Hardcoded Password",
        "pattern": re.compile(r'(?i)(?:password|passwd|pwd)[^=:]*[:=]\s*(["\'])(?!\1)(.{4,200})\1'),
        "severity": "HIGH",
        "tip": "Load passwords from environment variables or a secrets vault.",
    },
    {
        "name": "Hardcoded High-Entropy Secret",
        "pattern": re.compile(r'(?i)(?:secret|token|api_key|apikey|auth_key|private_key)[^=:]*[:=]\s*(["\'])([A-Za-z0-9+/=_\-]{32,})\1'),
        "severity": "HIGH",
        "tip": "Move secrets to environment variables or a secrets manager.",
    },
    {
        "name": "Hardcoded Public IP Address",
        "pattern": re.compile(r"\b(?!(?:127\.|0\.|192\.168\.|10\.))(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
        "severity": "MEDIUM",
        "tip": "Do not hardcode raw public IP addresses. Use domain names or environment variables.",
    },
    {
        "name": "Exposed UPI ID / Financial VPA Handle",
        "pattern": re.compile(r"[\w.\-_]+@(?:upi|ybl|ibh|oksbi|okaxis|paytm|barodampay|ikwik)"),
        "severity": "HIGH",
        "tip": "Exposed Financial UPI ID detected. This leaks traceable digital footprints. Remove it immediately.",
    }
]

SEVERITY_COLOR = {
    "HIGH":   RED    + BOLD,
    "MEDIUM": YELLOW + BOLD,
    "LOW":    CYAN   + BOLD,
}

def scan_file(filepath):
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            in_multiline_string = False
            for line_no, line in enumerate(fh, start=1):
                clean_line = line.strip()
                if not clean_line:
                    continue

                quotes_3_double = line.count('"""')
                quotes_3_single = line.count("'''")
                
                if (quotes_3_double % 2) != 0 or (quotes_3_single % 2) != 0:
                    in_multiline_string = not in_multiline_string
                    continue

                if in_multiline_string:
                    continue

                if "# nosec" in line or "// nosec" in line:
                    continue

                if "//" in line and not ("http://" in line or "https://" in line):
                    check_line = line.split("//")[0]
                elif "#" in line:
                    check_line = line.split("#")[0]
                else:
                    check_line = line
                
                for rule in RULES:
                    if rule["pattern"].search(check_line):
                        findings.append({
                            "file":     filepath,
                            "line":     line_no,
                            "severity": rule["severity"],
                            "issue":    rule["name"],
                            "tip":      rule["tip"],
                            "snippet":  line.rstrip()[:120],
                        })
                        break 
    except (OSError, PermissionError) as exc:
        print(colorize(f"  [SKIP] Cannot read '{filepath}': {exc}", DIM))
    return findings

def collect_files(path):
    TEXT_EXTENSIONS = {
        ".py", ".js", ".ts", ".jsx", ".tsx",
        ".java", ".go", ".rb", ".php", ".cs",
        ".env", ".cfg", ".ini", ".toml", ".yaml", ".yml",
        ".json", ".xml", ".sh", ".bash", ".zsh",
        ".tf", ".hcl", ".conf", ".properties",
    }
    if os.path.isfile(path):
        return [path]
    collected = []
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for filename in files:
            _, ext = os.path.splitext(filename)
            if ext.lower() in TEXT_EXTENSIONS or ext == "":
                collected.append(os.path.join(root, filename))
    return sorted(collected)

def print_finding(finding):
    sev   = finding["severity"]
    color = SEVERITY_COLOR.get(sev, "")
    
    line_label = colorize(f" Line {finding['line']} ", BOLD, color)
    issue_name = colorize(finding["issue"], BOLD)
    sev_badge  = colorize(f" {sev} ", BOLD, color)
    
    print(f"  ┌─{line_label}─┤ {sev_badge} ├──────────────")
    print(f"  │ {colorize('Issue :', BOLD)} {issue_name}")
    
    snippet = finding['snippet'].strip()
    if len(snippet) > 55:
        snippet = snippet[:52] + "..."
        
    print(f"  │ {colorize('Code  :', BOLD)} {colorize(snippet, DIM)}")
    print(f"  │ {colorize('Fix   :', BOLD)} {colorize(finding['tip'], GREEN)}")
    print(f"  └────────────────────────────────────────")
    print()

def print_summary(total_files, findings, elapsed):
    high   = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low    = sum(1 for f in findings if f["severity"] == "LOW")
    total  = len(findings)
    print(colorize("─" * 58, DIM))
    print(colorize(" SCAN SUMMARY", BOLD + YELLOW))
    print(colorize("─" * 58, DIM))
    print(f"  Files scanned   : {colorize(str(total_files), BOLD)}")
    print(f"  Total issues    : {colorize(str(total), BOLD)}")
    print(f"  ├─ HIGH         : {colorize(str(high),   RED    + BOLD)}")
    print(f"  ├─ MEDIUM       : {colorize(str(medium), YELLOW + BOLD)}")
    print(f"  └─ LOW          : {colorize(str(low),    CYAN   + BOLD)}")
    print(f"  Execution time  : {elapsed:.3f}s")
    print(colorize("─" * 58, DIM))
    if high > 0:
        print(colorize(ANGRY_CAT, RED + BOLD))
        print(colorize("  HISS! Fix your trash code, human!", RED + BOLD))
        print(colorize("  HIGH severity issues detected. Do NOT ship this.", RED))
    elif total == 0:
        print(colorize("\n All clear! No issues detected. Good human. \n", GREEN ))
    else:
        print(colorize(f"\n Review the {total} issue(s) above before shipping.\n", YELLOW))

def show_help():
    print(colorize(WELCOME_CAT, YELLOW + BOLD))
    print(colorize("  hisslock CLI — Static Secret & Vulnerability Scanner!", BOLD + CYAN))
    print(colorize("  100% Safe and sure | Pure Python, Zero Dependencies\n", DIM))
    print(colorize("  How To USE", BOLD))
    print("    python hisslock.py --path <file_or_directory> [--json]\n")
    print(colorize("  OPTIONS", BOLD))
    print(f"    {colorize('--path ', CYAN)}       File or directory to scan  {colorize('(required)', DIM)}")
    print(f"    {colorize('--json',CYAN)}        Dump findings to hisslock_report.json")
    print(f"    {colorize('-h, --help',  CYAN)}    Show help menu\n")
    print(colorize("  DETECTS", BOLD))
    print("   AWS/GCP/GitHub keys · Hardcoded passwords · eval/exec")
    print("   Internal API endpoints · Bearer tokens · Private API keys") 
    print("   Weak hashes · SSL bypasses · Debug flags · and more\n")
    print(colorize("  EXAMPLES", BOLD))
    print(f"    {colorize('$', DIM)} python hisslock.py --path ./myproject")
    print(f"    {colorize('$', DIM)} python hisslock.py --path secrets.env --json\n")
    print("   Append `# nosec` or `// nosec` to ignore Line.\n   Give space between # and nosec.")
    print(colorize("  " + "─" * 54, DIM))
    print(colorize("  Made by RohanCodx with the help of Elon Musk. \n" , DIM))

def build_parser():
    parser = argparse.ArgumentParser(prog="hisslock", add_help=False)
    parser.add_argument("--path", metavar="PATH", default=None)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("-h", "--help", action="store_true", default=False)
    return parser

def main():
    parser = build_parser()
    args   = parser.parse_args()

    if args.help or not args.path:
        show_help()
        sys.exit(0)

    print(colorize(WELCOME_CAT, YELLOW + BOLD))
   
    target = args.path
    if not os.path.exists(target):
        print(colorize(ANGRY_CAT, RED + BOLD))
        print(colorize(f"  HISS!  Path not found: '{target}'", RED + BOLD))
        print(colorize("  Double-check your --path argument, human.", RED))
        sys.exit(1)

    files = collect_files(target)
    if not files:
        print(colorize("  No scannable files found at the given path.", YELLOW))
        sys.exit(0)

    print(colorize(f"\n   Scanning {len(files)} file(s) in: {target} [Using 2 CPU Cores]\n", GREEN))

    start_time   = datetime.now()
    all_findings = []

    # यहाँ हुआ बदलाव: ProcessPoolExecutor का उपयोग 2 max_workers के साथ किया गया है
    # यह एक फ़ाइल को स्कैन करते ही उसका रिजल्ट टर्मिनल पर प्रिंट कर देगा (Real-time tracking)
    with ProcessPoolExecutor(max_workers=2) as executor:
        # सभी फ़ाइलों को 2 अलग-अलग प्रोसेस में समानांतर (parallel) सबमिट करना
        future_to_file = {executor.submit(scan_file, filepath): filepath for filepath in files}
        
        for future in future_to_file:
            filepath = future_to_file[future]
            try:
                findings = future.result()
                if findings:
                    rel = os.path.relpath(filepath)
                    print(colorize(f"   {rel}", BOLD))
                    print(colorize("  " + "─" * 56, DIM))
                    for f in findings:
                        print_finding(f)
                    all_findings.extend(findings)
            except Exception as exc:
                print(colorize(f"  [ERROR] Fails to scan '{filepath}': {exc}", RED))
            
    seen = set()
    deduped = []
    for f in all_findings:
        key = (f["file"], f["line"], f["issue"], f["snippet"])
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    all_findings = deduped

    elapsed = (datetime.now() - start_time).total_seconds()
    print_summary(len(files), all_findings, elapsed)

    if args.json:
        report_path = "hisslock_report.json"
        report = {
            "tool": "hisslock CLI",
            "scanned_at":   datetime.now().isoformat(),
            "target":       target,
            "total_files":  len(files),
            "total_issues": len(all_findings),
            "findings":     all_findings,
        }
        with open(report_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(colorize(f" JSON report saved → {report_path}", GREEN))
        
    high_count = sum(1 for f in all_findings if f["severity"] == "HIGH")
    sys.exit(1 if high_count > 0 else 0)

if __name__ == '__main__':
    main()
    