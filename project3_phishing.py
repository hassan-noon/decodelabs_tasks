import re

KNOWN_BRANDS = [
    "google", "microsoft", "paypal", "amazon", "apple", "netflix",
    "linkedin", "facebook", "instagram", "chatgpt", "openai", "dropbox",
    "whatsapp", "twitter", "github", "zoom", "decodelabs"
]

URGENCY_KEYWORDS = [
    "urgent", "immediately", "action required", "account locked",
    "expires in", "within 24 hours", "asap", "right now",
    "your account has been", "suspended", "limited", "verify now"
]

AUTHORITY_KEYWORDS = [
    "ceo", "it support", "it department", "hr department",
    "human resources", "management", "executive", "director",
    "law enforcement", "legal action", "irs", "government"
]

FEAR_GREED_KEYWORDS = [
    "you have won", "congratulations", "claim your prize",
    "legal action", "lawsuit", "penalty", "arrested",
    "unauthorized access", "suspicious activity", "breach"
]

SENSITIVE_REQUEST_KEYWORDS = [
    "password", "credit card", "bank account", "wire transfer",
    "mfa code", "one-time code", "ssn", "social security",
    "billing information", "payment details", "credentials"
]

BYPASS_KEYWORDS = [
    "do not discuss", "strictly confidential", "bypass",
    "do not tell", "between us", "keep this private",
    "don't mention", "secret"
]

DANGEROUS_EXTENSIONS = [".exe", ".iso", ".js", ".scr", ".bat", ".vbs", ".zip", ".rar"]

def banner():
    print("""
          PHISHING TRIAGE TOOLKIT — DecodeLabs P3  
          Analyze 
          Classify
          Defend
          PauseVerify
          Report
""")

def analyze_domain(domain):
    flags = []
    domain_lower = domain.lower()
    parts = domain_lower.replace("https://", "").replace("http://", "").split("/")[0]
    segments = parts.split(".")
    tld_index = len(segments) - 1

    if tld_index >= 2:
        subdomain_chain = ".".join(segments[:-2])
        root = ".".join(segments[-2:])
        for brand in KNOWN_BRANDS:
            if brand in subdomain_chain and brand not in root:
                flags.append(
                    f"SUBDOMAIN TRAP: '{brand}' in subdomain but true root is '{root}'. "
                    f"Read right-to-left — real domain is '{root}'."
                )
    root_domain = ".".join(segments[-2:]) if len(segments) >= 2 else domain_lower
    for brand in KNOWN_BRANDS:
        if brand in root_domain and root_domain != f"{brand}.com":
            if any(c.isdigit() for c in root_domain):
                flags.append(f"TYPOSQUATTING: '{root_domain}' substitutes digits for letters.")
            elif f"{brand}-" in root_domain or f"-{brand}" in root_domain:
                flags.append(f"COMBOSQUATTING: '{root_domain}' appends words to brand name.")
            elif root_domain != f"{brand}.com":
                flags.append(f"LOOKALIKE DOMAIN: '{root_domain}' resembles '{brand}.com' but is not.")

    if not parts.endswith(".com") and not parts.endswith(".org") and not parts.endswith(".net"):
        unusual_tld = parts.split(".")[-1]
        if unusual_tld not in ["edu", "gov", "io", "co", "uk", "ca", "au", "de"]:
            flags.append(f"UNUSUAL TLD: '.{unusual_tld}' is uncommon and often used in phishing.")
    return flags
def analyze_sender(sender):
    flags = []
    sender_lower = sender.lower()
    match = re.search(r'<(.+?)>', sender)
    if match:
        display_name = sender_lower.split("<")[0].strip()
        actual_email = match.group(1)
        actual_domain = actual_email.split("@")[-1] if "@" in actual_email else ""

        for brand in KNOWN_BRANDS:
            if brand in display_name and brand not in actual_domain:
                flags.append(
                    f"SENDER-DOMAIN MISMATCH: Display name suggests '{brand}' "
                    f"but actual email is '{actual_email}'. Classic display name spoofing."
                )

        if actual_domain in ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"]:
            for brand in KNOWN_BRANDS:
                if brand in display_name:
                    flags.append(
                        f"FREE EMAIL IMPERSONATION: '{brand}' impersonated via personal "
                        f"'{actual_domain}' address. Legitimate companies use corporate domains."
                    )
    return flags

def analyze_subject(subject):
    flags = []
    subject_lower = subject.lower()

    if subject_lower.startswith("fw:") or subject_lower.startswith("fwd:"):
        flags.append(
            "FAKE FORWARDED CHAIN: FW:/FWD: prefix detected. Could be a fake thread "
            "designed to manufacture context and urgency."
        )
    for keyword in URGENCY_KEYWORDS:
        if keyword in subject_lower:
            flags.append(
                f"URGENCY TRIGGER IN SUBJECT: '{keyword}' detected. Designed to trigger "
                "fight-or-flight response and bypass rational verification."
            )
            break
    return flags

def analyze_body(body):
    flags = []
    body_lower = body.lower()

    for keyword in URGENCY_KEYWORDS:
        if keyword in body_lower:
            flags.append(f"URGENCY: '{keyword}' — Artificial time pressure detected.")
            break

    for keyword in AUTHORITY_KEYWORDS:
        if keyword in body_lower:
            flags.append(f"AUTHORITY: '{keyword}' — Impersonation of authority figure.")
            break

    for keyword in FEAR_GREED_KEYWORDS:
        if keyword in body_lower:
            flags.append(f"FEAR/GREED: '{keyword}' — Emotional manipulation detected.")
            break

    for keyword in SENSITIVE_REQUEST_KEYWORDS:
        if keyword in body_lower:
            flags.append(
                f"SENSITIVE DATA REQUEST: '{keyword}' — Legitimate services never request "
                "this over email."
            )

    for keyword in BYPASS_KEYWORDS:
        if keyword in body_lower:
            flags.append(
                f"BYPASS REQUEST: '{keyword}' — Instruction to skip normal security procedures. "
                "Red Flag 5: Urgent Bypass Request."
            )

    urls = re.findall(r'https?://[^\s<>"]+', body)
    for url in urls:
        domain_flags = analyze_domain(url)
        flags.extend(domain_flags)

    if not urls and re.search(r'\d{3}[-.\s]?\d{3}[-.\s]?\d{4}', body):
        flags.append(
            "CALLBACK PHISHING (TOAD): No URLs found but a phone number is present. "
            "Attacker redirects victim to a live social engineering call."
        )

    for ext in DANGEROUS_EXTENSIONS:
        if ext in body_lower:
            flags.append(
                f"DANGEROUS ATTACHMENT TYPE: '{ext}' file mentioned. "
                "Uncommon extensions are common malware delivery vectors."
            )
    return flags

def triage_verdict(total_flags):
    if total_flags == 0:
        return "SAFE", "Close. No indicators of phishing detected."
    elif total_flags <= 2:
        return "SUSPICIOUS", "Warn User. Treat with caution. Verify via out-of-band channel before acting."
    else:
        return "MALICIOUS", "Block Domain & Escalate. Do NOT click links, reply, or delete — report to security team."

def print_report(verdict, action, flags, sender, subject):
    print("\n" + "=" * 62)
    print("  PHISHING TRIAGE REPORT")
    print("=" * 62)
    print(f"  Sender:  {sender}")
    print(f"  Subject: {subject}")
    print("-" * 62)
    if flags:
        print(f"\n  RED FLAGS DETECTED ({len(flags)}):\n")
        for i, flag in enumerate(flags, 1):
            print(f"  [{i}] {flag}\n")
    else:
        print("\n  No red flags detected.\n")

    print("-" * 62)
    verdict_icons = {"SAFE": "✅", "SUSPICIOUS": "⚠️ ", "MALICIOUS": "🚨"}
    print(f"\n  VERDICT:  {verdict_icons[verdict]} {verdict}")
    print(f"  ACTION:   {action}")

    print("\n  TRIAGE PROCEDURE:")
    if verdict == "SAFE":
        print("1 PAUSE  No triggers identified")
        print("2 VERIFY No action required")
        print("3 REPORT Close the email")
    elif verdict == "SUSPICIOUS":
        print("1 PAUSE  Stop interacting with the message")
        print("2 VERIFY Call sender via known directory number")
        print("3 REPORT  Flag for security review")
    else:
        print("1 PAUSE  Do NOT click, reply, or download anything")
        print("2 VERIFY  Confirm with IT via a separate channel")
        print("3 REPORT  Use reporting plugin. Do NOT delete.")
    print("\n" + "=" * 62)
def run_demo():
    print("\n  [DEMO MODE — Running 3 sample emails]\n")
    samples = [
        {
            "sender": "Microsoft Support <support@logins-updates.com>",
            "subject": "FW: Urgent: Your Account Security Alert",
            "body": (
                "Dear user, your Microsoft account has been suspended due to suspicious activity. "
                "You must verify your credentials immediately or your account will be permanently deleted. "
                "Click here to verify: https://microsoft.account-verify.login-secure.com/verify "
                "Attachment: Security_Update_2024.iso"
            )
        },
        {
            "sender": "CEO - STRICTLY CONFIDENTIAL <ceo.urgent@executive-update.com>",
            "subject": "IMMEDIATE ACTION REQUIRED: Transfer Authorization",
            "body": (
                "URGENT: Process the attached wire transfer instruction immediately. "
                "This is critical and must remain STRICTLY CONFIDENTIAL. "
                "Do not discuss with anyone. Bypass standard procedure. "
                "I lost my wallet at the airport. Need you to wire transfer funds before close of business. "
                "Do not tell HR about this."
            )
        },
        {
            "sender": "Project Manager <sarah.lee@company.com>",
            "subject": "Q3 Project Status Update - Non-Urgent",
            "body": (
                "Hi Team, please review the attached project status for Q3 at your earliest convenience. "
                "No immediate action is required. Thanks, Sarah."
            )
        }
    ]

    for i, sample in enumerate(samples, 1):
        print(f"\n{'─' * 62}")
        print(f"  SAMPLE EMAIL {i}")
        print(f"{'─' * 62}")
        all_flags = []
        all_flags.extend(analyze_sender(sample["sender"]))
        all_flags.extend(analyze_subject(sample["subject"]))
        all_flags.extend(analyze_body(sample["body"]))
        verdict, action = triage_verdict(len(all_flags))
        print_report(verdict, action, all_flags, sample["sender"], sample["subject"])

def manual_mode():
    print("\n  Enter email details for triage analysis.")
    print("  (Leave blank and press Enter to skip a field)\n")
    sender  = input("  From: ").strip()
    subject = input("  Subject: ").strip()
    print("  Body (press Enter twice when done):")
    body_lines = []
    while True:
        line = input()
        if line == "":
            break
        body_lines.append(line)
    body = " ".join(body_lines)

    all_flags = []
    if sender:  all_flags.extend(analyze_sender(sender))
    if subject: all_flags.extend(analyze_subject(subject))
    if body:    all_flags.extend(analyze_body(body))

    verdict, action = triage_verdict(len(all_flags))
    print_report(verdict, action, all_flags, sender or "N/A", subject or "N/A")
def main():
    banner()
    print("  [1] Run Demo (3 sample emails)")
    print("  [2] Analyze your own email")
    print("  [0] Exit\n")
    choice = input("  Select: ").strip()
    if choice == "1":
        run_demo()
    elif choice == "2":
        manual_mode()
    elif choice == "0":
        print("\n  Session terminated.\n")
    else:
        print("  Invalid option.")
main()