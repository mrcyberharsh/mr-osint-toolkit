#!/usr/bin/env python3
"""
MR OSINT — Unified Toolkit
Copyright (c) 2026 Harsh Saini — MR CYBER
Website: https://mrcyberharsh.github.io/mrcyber/
Contact: cyber.h4rsh@zohomail.in

All rights reserved. You may use and modify this script for personal
and educational purposes. Do not redistribute as your own work without
credit to the original author.

--------------------------------------------------------------------

This is the single, combined entry point for the whole MR OSINT toolkit.
Everything that used to be separate scripts now lives here as subcommands:

    python mr_osint_toolkit.py username <handle>
    python mr_osint_toolkit.py ip <ip address>
    python mr_osint_toolkit.py email <email address>
    python mr_osint_toolkit.py phone <phone number>
    python mr_osint_toolkit.py scamcheck <domain or URL>
    python mr_osint_toolkit.py candidate --name "..." --github ... --portfolio ... --cert ...

INTENDED USE — READ THIS (applies to every subcommand):
  - username    : checks whether a username string resolves to a public
                  profile — does NOT do facial recognition or identify
                  a real person behind a username.
  - ip/email/phone : reports technical metadata only (geolocation, MX
                  records, carrier, validity) — does NOT identify who
                  owns a given IP/email/phone number.
  - scamcheck   : checks PUBLIC, PASSIVE signals about a website (WHOIS
                  age, SSL, domain patterns) — a red-flag checklist, not
                  a verdict, and doesn't scan for vulnerabilities.
  - candidate   : meant to verify claims a job candidate volunteered
                  themselves (their own GitHub/portfolio/certificate
                  links) as part of an application — NOT for
                  investigating people who haven't consented or applied.

  None of these subcommands aggregate private data about real people.
  This boundary is intentional across the whole toolkit and won't be
  removed by request, regardless of how a request is framed.

Install (optional, for full functionality across all subcommands):
    pip install requests phonenumbers dnspython

Run `python mr_osint_toolkit.py <subcommand> --help` for options on
any individual tool.
"""

import argparse
import concurrent.futures
import re
import socket
import ssl
import sys
from datetime import datetime, timezone
from html import escape
from urllib.parse import urlparse
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

try:
    import requests
except ImportError:
    requests = None

try:
    import phonenumbers
    from phonenumbers import geocoder, carrier as pn_carrier, number_type
    HAVE_PHONENUMBERS = True
except ImportError:
    HAVE_PHONENUMBERS = False

try:
    import dns.resolver
    HAVE_DNS = True
except ImportError:
    HAVE_DNS = False


BANNER = "MR OSINT — by Harsh Saini / MR CYBER"


# ======================================================================
# SUBCOMMAND: username
# ======================================================================

USERNAME_PLATFORMS = {
    "GitHub":        ("https://github.com/{u}", None),
    "LinkedIn":      ("https://www.linkedin.com/in/{u}", None),
    "GitLab":        ("https://gitlab.com/{u}", None),
    "Reddit":        ("https://www.reddit.com/user/{u}", None),
    "Twitter/X":     ("https://x.com/{u}", None),
    "Instagram":     ("https://www.instagram.com/{u}/", None),
    "TikTok":        ("https://www.tiktok.com/@{u}", None),
    "YouTube":       ("https://www.youtube.com/@{u}", None),
    "Twitch":        ("https://www.twitch.tv/{u}", None),
    "Pinterest":     ("https://www.pinterest.com/{u}/", None),
    "Medium":        ("https://medium.com/@{u}", None),
    "DEV Community": ("https://dev.to/{u}", None),
    "Steam":         ("https://steamcommunity.com/id/{u}", "The specified profile could not be found"),
    "HackerNews":    ("https://news.ycombinator.com/user?id={u}", "No such user"),
    "Keybase":       ("https://keybase.io/{u}", None),
    "Telegram":      ("https://t.me/{u}", None),
    "Facebook":      ("https://www.facebook.com/{u}", None),
    "SoundCloud":    ("https://soundcloud.com/{u}", None),
    "Spotify":       ("https://open.spotify.com/user/{u}", None),
    "Roblox":        ("https://www.roblox.com/user.aspx?username={u}", "Page cannot be found"),
    "Docker Hub":    ("https://hub.docker.com/u/{u}", None),
}

UA_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    )
}


def username_check_platform(name, url_template, not_found_marker, username, timeout):
    url = url_template.format(u=username)
    try:
        resp = requests.get(url, headers=UA_HEADERS, timeout=timeout, allow_redirects=True)
    except requests.RequestException as e:
        return name, url, "ERROR", str(e)

    if resp.status_code == 404:
        return name, url, "NOT FOUND", None

    if resp.status_code == 200:
        if not_found_marker and not_found_marker.lower() in resp.text.lower():
            return name, url, "NOT FOUND", None
        return name, url, "FOUND", None

    return name, url, f"UNKNOWN ({resp.status_code})", None


def cmd_username(args):
    if requests is None:
        print("The 'requests' library isn't installed. Run: pip install requests")
        return

    if not args.username or any(c.isspace() for c in args.username):
        print("Please provide a single username with no spaces.", file=sys.stderr)
        sys.exit(1)

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {
            pool.submit(username_check_platform, name, tmpl, marker, args.username, args.timeout): name
            for name, (tmpl, marker) in USERNAME_PLATFORMS.items()
        }
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    order = {"FOUND": 0, "NOT FOUND": 1}
    results.sort(key=lambda r: (order.get(r[2], 2), r[0]))

    found = [r for r in results if r[2] == "FOUND"]
    not_found = [r for r in results if r[2] == "NOT FOUND"]
    errored = [r for r in results if r[2] not in ("FOUND", "NOT FOUND")]

    print(f"\n{BANNER}")
    print(f"Username report for: {args.username}")
    print("=" * 60)

    print(f"\n[+] Found on {len(found)} platform(s):")
    for name, url, status, _ in found:
        print(f"    {name:<16} {url}")

    print(f"\n[-] Not found on {len(not_found)} platform(s):")
    for name, url, status, _ in not_found:
        print(f"    {name:<16}")

    if errored:
        print(f"\n[!] Could not check {len(errored)} platform(s) (network/site issue):")
        for name, url, status, err in errored:
            print(f"    {name:<16} {status}")

    print("\nNote: a 'FOUND' result means a public profile page exists at that URL —")
    print("always verify manually before drawing conclusions; some platforms reserve")
    print("usernames or show a generic page even when no real account is active.")
    print("\nLinkedIn specifically blocks automated requests and usually returns a")
    print("login wall regardless of whether the profile exists — treat its result")
    print("as unreliable and verify LinkedIn profiles manually.\n")


# ======================================================================
# SUBCOMMAND: ip / email / phone
# ======================================================================

DISPOSABLE_DOMAINS = {
    "mailinator.com", "10minutemail.com", "guerrillamail.com", "tempmail.com",
    "yopmail.com", "trashmail.com", "getnada.com", "throwawaymail.com",
    "fakeinbox.com", "sharklasers.com",
}

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


def cmd_ip(args):
    ip = args.ip
    print(f"\n{BANNER}")
    print(f"IP lookup for: {ip}")
    print("=" * 60)

    if requests is None:
        print("The 'requests' library isn't installed. Run: pip install requests")
        return

    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=8)
    except Exception as e:
        print(f"Lookup failed: could not reach ip-api.com ({e})")
        return

    try:
        data = resp.json()
    except ValueError:
        print(f"Lookup failed: got an unexpected response (HTTP {resp.status_code}).")
        print("This can happen if your network blocks the request or you're rate-limited.")
        return

    if data.get("status") != "success":
        print(f"Could not resolve info for {ip}: {data.get('message', 'unknown error')}")
        return

    fields = [
        ("Country", data.get("country")), ("Region", data.get("regionName")),
        ("City", data.get("city")), ("ZIP", data.get("zip")),
        ("Latitude/Longitude", f"{data.get('lat')}, {data.get('lon')}"),
        ("Timezone", data.get("timezone")), ("ISP", data.get("isp")),
        ("Organization", data.get("org")), ("ASN", data.get("as")),
    ]
    for label, value in fields:
        print(f"  {label:<20} {value}")

    print("\nNote: this is network/ISP-level geolocation, not a precise physical")
    print("address — IP geolocation is often accurate to city level at best, and")
    print("can be wrong for VPNs, mobile carriers, or corporate NAT ranges.\n")


def cmd_email(args):
    email = args.email
    print(f"\n{BANNER}")
    print(f"Email check for: {email}")
    print("=" * 60)

    if not EMAIL_REGEX.match(email):
        print("  Syntax valid:       NO — this doesn't look like a valid email address.")
        return

    domain = email.split("@", 1)[1].lower()
    print(f"  Syntax valid:       YES")
    print(f"  Domain:             {domain}")
    print(f"  Disposable domain:  {'YES — likely a temporary/throwaway address' if domain in DISPOSABLE_DOMAINS else 'no (not in known disposable list)'}")

    if HAVE_DNS:
        try:
            answers = dns.resolver.resolve(domain, "MX")
            mx_hosts = sorted(str(r.exchange).rstrip(".") for r in answers)
            print(f"  MX records:         found ({len(mx_hosts)}) — domain can plausibly receive mail")
            for host in mx_hosts[:5]:
                print(f"                        - {host}")
        except Exception:
            print("  MX records:         none found — domain likely can't receive mail")
    else:
        print("  MX records:         skipped (install dnspython for this check: pip install dnspython)")

    print("\nNote: this confirms the email is well-formed and the domain can receive")
    print("mail — it does NOT confirm the address is registered, active, or tell you")
    print("who owns it. This tool will not attempt to identify the account holder.\n")


def cmd_phone(args):
    number = args.number
    print(f"\n{BANNER}")
    print(f"Phone check for: {number}")
    print("=" * 60)

    if HAVE_PHONENUMBERS:
        try:
            parsed = phonenumbers.parse(number, None)
        except phonenumbers.NumberParseException as e:
            print(f"  Could not parse number: {e}")
            print("  Tip: include the country code, e.g. +14155552671")
            return

        valid = phonenumbers.is_valid_number(parsed)
        print(f"  Valid number:       {'YES' if valid else 'NO'}")
        print(f"  E.164 format:       {phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)}")
        print(f"  Country/region:     {geocoder.description_for_number(parsed, 'en') or 'unknown'}")
        print(f"  Country code:       +{parsed.country_code}")

        type_map = {
            phonenumbers.PhoneNumberType.MOBILE: "Mobile",
            phonenumbers.PhoneNumberType.FIXED_LINE: "Fixed line",
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed line or mobile",
            phonenumbers.PhoneNumberType.VOIP: "VoIP",
            phonenumbers.PhoneNumberType.TOLL_FREE: "Toll-free",
            phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium rate",
        }
        num_type = number_type(parsed)
        print(f"  Number type:        {type_map.get(num_type, 'Unknown/other')}")

        carrier_name = pn_carrier.name_for_number(parsed, "en")
        print(f"  Carrier:            {carrier_name if carrier_name else 'not available for this number/region'}")
    else:
        print("  Full validation needs the 'phonenumbers' library.")
        print("  Install it with: pip install phonenumbers\n")
        cleaned = re.sub(r"[^\d+]", "", number)
        looks_valid = bool(re.match(r"^\+?\d{8,15}$", cleaned))
        print(f"  Basic format check: {'plausible' if looks_valid else 'does not look like a valid number'}")

    print("\nNote: this reports technical metadata about the number (validity, type,")
    print("carrier) — it does NOT identify who the number belongs to. This tool will")
    print("not attempt to find the owner's name or personal details.\n")


# ======================================================================
# SUBCOMMAND: scamcheck
# ======================================================================

WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com",
    "org": "whois.pir.org", "info": "whois.afilias.net", "biz": "whois.biz",
    "in": "whois.registry.in", "co": "whois.nic.co", "io": "whois.nic.io",
    "me": "whois.nic.me", "app": "whois.nic.google", "dev": "whois.nic.google",
    "xyz": "whois.nic.xyz", "site": "whois.nic.site", "online": "whois.nic.online",
    "store": "whois.nic.store", "shop": "whois.nic.shop", "in.net": "whois.centralnic.com",
}

SUSPICIOUS_TLDS = {"xyz", "top", "gq", "tk", "ml", "cf", "ga", "buzz", "click", "work", "loan"}

BRAND_KEYWORDS = [
    "amazon", "flipkart", "paytm", "phonepe", "googlepay", "sbi", "hdfc", "icici",
    "axis", "irctc", "myntra", "meesho", "olx", "netflix", "instagram", "whatsapp",
]


def scam_get_registrable_domain(host):
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "net", "org") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def scam_whois_lookup(domain):
    tld = domain.split(".")[-1]
    server = WHOIS_SERVERS.get(tld)
    if not server:
        return None, f"No known WHOIS server for .{tld} — skipping domain-age check."

    try:
        with socket.create_connection((server, 43), timeout=8) as sock:
            sock.sendall((domain + "\r\n").encode())
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        text = response.decode(errors="ignore")
    except Exception as e:
        return None, f"WHOIS lookup failed: {e}"

    referral = re.search(r"Registrar WHOIS Server:\s*(\S+)", text, re.IGNORECASE)
    if referral and referral.group(1) not in (server, ""):
        try:
            with socket.create_connection((referral.group(1), 43), timeout=8) as sock:
                sock.sendall((domain + "\r\n").encode())
                response = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            text = response.decode(errors="ignore")
        except Exception:
            pass

    date_match = re.search(
        r"(?:Creation Date|Registered On|created|Domain Registration Date)[:\s]+([0-9T:\-\.Z]+)",
        text, re.IGNORECASE,
    )
    if not date_match:
        return None, "Could not parse a creation date from WHOIS data (registry format may differ)."

    raw_date = date_match.group(1).strip().rstrip("Z")
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%Y.%m.%d"):
        try:
            created = datetime.strptime(raw_date[:19], fmt)
            return created, None
        except ValueError:
            continue
    return None, f"Found a date but couldn't parse its format: {raw_date}"


def scam_check_ssl(host):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        issuer = dict(x[0] for x in cert.get("issuer", []))
        return {
            "valid": True,
            "issuer": issuer.get("organizationName", issuer.get("commonName", "unknown")),
            "expires": not_after,
        }, None
    except ssl.SSLCertVerificationError as e:
        return {"valid": False}, f"Certificate is present but not trusted/valid: {e}"
    except Exception as e:
        return None, f"Could not establish HTTPS connection: {e}"


def scam_check_reachability(url):
    try:
        req = Request(url, headers={"User-Agent": "Mozilla/5.0 (MR-OSINT scam checker)"})
        with urlopen(req, timeout=8) as resp:
            return True, resp.status
    except HTTPError as e:
        return True, e.code
    except URLError as e:
        return False, str(e.reason)
    except Exception as e:
        return False, str(e)


def scam_check_domain_patterns(domain):
    flags = []
    hyphen_count = domain.count("-")
    if hyphen_count >= 3:
        flags.append(f"Domain has {hyphen_count} hyphens — real brand domains rarely do this.")

    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
        flags.append("Domain looks like a raw IP address, not a real hostname.")

    tld = domain.split(".")[-1]
    if tld in SUSPICIOUS_TLDS:
        flags.append(f"Uses .{tld}, a TLD frequently abused for scam/spam sites (not proof by itself, but worth extra caution).")

    domain_lower = domain.lower()
    for brand in BRAND_KEYWORDS:
        if brand in domain_lower and not domain_lower.startswith(brand + "."):
            flags.append(f"Contains the brand name '{brand}' but isn't that brand's actual domain — common lookalike/phishing pattern.")
            break

    return flags


def cmd_scamcheck(args):
    target = args.target
    parsed = urlparse(target if "://" in target else f"https://{target}")
    host = parsed.netloc or parsed.path
    host = host.split(":")[0]
    domain = scam_get_registrable_domain(host)
    url = f"{parsed.scheme or 'https'}://{host}"

    print(f"\n{BANNER}")
    print(f"Scam website check for: {host}")
    print("=" * 60)

    risk_points = 0
    notes = []

    reachable, status = scam_check_reachability(url)
    if reachable:
        print(f"  Reachable:          YES (HTTP {status})")
    else:
        print(f"  Reachable:          NO ({status})")
        notes.append("Site did not respond — could be down, blocking automated requests, or fake.")
        risk_points += 1

    ssl_info, ssl_err = scam_check_ssl(host)
    if ssl_info and ssl_info.get("valid"):
        days_left = (ssl_info["expires"] - datetime.utcnow()).days
        print(f"  HTTPS/SSL:          valid — issued by {ssl_info['issuer']}, expires in {days_left} days")
        if days_left < 15:
            notes.append("SSL certificate expires very soon — could indicate an abandoned or low-effort site.")
            risk_points += 1
    else:
        print(f"  HTTPS/SSL:          NOT valid or not present — {ssl_err}")
        notes.append("No valid HTTPS — never enter payment or login details on a site without valid HTTPS.")
        risk_points += 3

    created, whois_err = scam_whois_lookup(domain)
    if created:
        age_days = (datetime.utcnow() - created).days
        age_years = age_days / 365.25
        print(f"  Domain age:         {age_days} days (~{age_years:.1f} years), registered {created.date()}")
        if age_days < 90:
            notes.append("Domain is less than 3 months old — very common trait of scam/fraud sites.")
            risk_points += 3
        elif age_days < 365:
            notes.append("Domain is under a year old — not necessarily a scam, but worth extra caution.")
            risk_points += 1
    else:
        print(f"  Domain age:         unavailable — {whois_err}")

    pattern_flags = scam_check_domain_patterns(domain)
    if pattern_flags:
        print(f"  Domain pattern flags:")
        for f in pattern_flags:
            print(f"    - {f}")
            risk_points += 2
    else:
        print(f"  Domain pattern flags: none found")

    print("\n" + "-" * 60)
    if risk_points >= 6:
        verdict = "HIGH RISK — multiple strong scam signals found."
    elif risk_points >= 3:
        verdict = "MODERATE RISK — some signals present, proceed with caution."
    elif risk_points >= 1:
        verdict = "LOW RISK — minor flags, likely fine but stay alert."
    else:
        verdict = "NO MAJOR RED FLAGS FOUND in these automated checks."
    print(f"  Verdict: {verdict}")

    if notes:
        print("\n  Why:")
        for n in notes:
            print(f"    - {n}")

    print(
        "\nImportant: this is a checklist based on public signals, not a guarantee.\n"
        "Legitimate new businesses can trigger some flags, and well-funded scams can\n"
        "avoid all of them. Always cross-check reviews, contact info, and use secure\n"
        "payment methods (never direct bank transfer to an unknown seller).\n"
    )


# ======================================================================
# SUBCOMMAND: candidate
# ======================================================================

CAND_ACCENT = "#0F6E56"


def cand_fetch_github(username):
    if requests is None:
        return None, "The 'requests' library isn't installed. Run: pip install requests"

    headers = {"Accept": "application/vnd.github+json", "User-Agent": "MR-OSINT-candidate-report"}
    try:
        user_resp = requests.get(f"https://api.github.com/users/{username}", headers=headers, timeout=8)
    except Exception as e:
        return None, f"Could not reach GitHub API: {e}"

    if user_resp.status_code == 404:
        return None, f"No GitHub user found for username '{username}'."
    if user_resp.status_code != 200:
        return None, f"GitHub API returned HTTP {user_resp.status_code} (possibly rate-limited — GitHub allows 60 unauthenticated requests/hour)."

    user = user_resp.json()

    repos = []
    try:
        repos_resp = requests.get(
            f"https://api.github.com/users/{username}/repos",
            params={"sort": "updated", "per_page": 100},
            headers=headers, timeout=8,
        )
        if repos_resp.status_code == 200:
            repos = repos_resp.json()
    except Exception:
        pass

    lang_counts = {}
    for r in repos:
        lang = r.get("language")
        if lang:
            lang_counts[lang] = lang_counts.get(lang, 0) + 1
    top_languages = sorted(lang_counts.items(), key=lambda x: -x[1])[:5]
    top_repos = sorted(repos, key=lambda r: r.get("stargazers_count", 0), reverse=True)[:5]

    last_activity = None
    if repos:
        dates = [r.get("pushed_at") for r in repos if r.get("pushed_at")]
        if dates:
            last_activity = max(dates)

    created = user.get("created_at")
    account_age_days = None
    if created:
        try:
            created_dt = datetime.strptime(created, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            account_age_days = (datetime.now(timezone.utc) - created_dt).days
        except ValueError:
            pass

    return {
        "username": username, "profile_url": user.get("html_url", f"https://github.com/{username}"),
        "name": user.get("name"), "bio": user.get("bio"), "company": user.get("company"),
        "location": user.get("location"), "blog": user.get("blog"),
        "public_repos": user.get("public_repos"), "followers": user.get("followers"),
        "created_at": created, "account_age_days": account_age_days,
        "top_languages": top_languages,
        "top_repos": [
            {"name": r.get("name"), "url": r.get("html_url"), "stars": r.get("stargazers_count", 0),
             "description": r.get("description"), "language": r.get("language")}
            for r in top_repos
        ],
        "last_activity": last_activity,
    }, None


def cand_check_url(url, timeout=8):
    if requests is None:
        return False, "requests library not installed", None
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0 (MR-OSINT candidate report)"})
        title = None
        match = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
        if match:
            title = re.sub(r"\s+", " ", match.group(1)).strip()[:120]
        return resp.status_code < 400, resp.status_code, title
    except Exception as e:
        return False, str(e), None


def cand_build_html_report(candidate_name, github_data, github_err, portfolio_url, portfolio_result, cert_results):
    now = datetime.now().strftime("%d %b %Y, %H:%M")

    def section(title, body):
        return f'<div class="section"><h2>{escape(title)}</h2>{body}</div>'

    if github_data:
        langs_html = "".join(f'<span class="chip">{escape(l)} ({c})</span>' for l, c in github_data["top_languages"]) or "<span class='muted'>No language data available</span>"
        repos_html = "".join(
            f'<div class="repo-row"><a href="{escape(r["url"])}" target="_blank">{escape(r["name"])}</a> '
            f'<span class="stars">★ {r["stars"]}</span><br><span class="muted">{escape(r["description"] or "No description")}</span></div>'
            for r in github_data["top_repos"]
        ) or "<span class='muted'>No public repositories found</span>"

        age_str = f'{github_data["account_age_days"]} days (~{github_data["account_age_days"]/365.25:.1f} years)' if github_data["account_age_days"] else "unknown"

        gh_body = f"""
        <table class="info-table">
          <tr><td>Profile</td><td><a href="{escape(github_data['profile_url'])}" target="_blank">{escape(github_data['profile_url'])}</a></td></tr>
          <tr><td>Display name</td><td>{escape(github_data['name'] or '—')}</td></tr>
          <tr><td>Bio</td><td>{escape(github_data['bio'] or '—')}</td></tr>
          <tr><td>Company</td><td>{escape(github_data['company'] or '—')}</td></tr>
          <tr><td>Location</td><td>{escape(github_data['location'] or '—')}</td></tr>
          <tr><td>Account age</td><td>{age_str}</td></tr>
          <tr><td>Public repos</td><td>{github_data['public_repos']}</td></tr>
          <tr><td>Followers</td><td>{github_data['followers']}</td></tr>
          <tr><td>Last activity</td><td>{escape(github_data['last_activity'] or 'unknown')}</td></tr>
        </table>
        <h3>Top languages (by repo count)</h3>
        <div class="chip-row">{langs_html}</div>
        <h3>Most-starred repositories</h3>
        {repos_html}
        """
    else:
        gh_body = f'<p class="warn">Could not verify GitHub profile — {escape(github_err or "unknown error")}</p>'

    if portfolio_url:
        reachable, status, title = portfolio_result
        status_class = "ok" if reachable else "bad"
        port_body = f"""
        <table class="info-table">
          <tr><td>URL</td><td><a href="{escape(portfolio_url)}" target="_blank">{escape(portfolio_url)}</a></td></tr>
          <tr><td>Status</td><td class="{status_class}">{"Reachable" if reachable else "NOT reachable"} ({escape(str(status))})</td></tr>
          <tr><td>Page title</td><td>{escape(title or '—')}</td></tr>
        </table>
        """
    else:
        port_body = "<p class='muted'>No portfolio URL provided.</p>"

    if cert_results:
        rows = ""
        for url, (reachable, status, title) in cert_results:
            status_class = "ok" if reachable else "bad"
            rows += f"""
            <tr>
              <td><a href="{escape(url)}" target="_blank">{escape(url[:60])}{'...' if len(url) > 60 else ''}</a></td>
              <td class="{status_class}">{"Reachable" if reachable else "BROKEN"} ({escape(str(status))})</td>
              <td>{escape(title or '—')}</td>
            </tr>
            """
        cert_body = f"""
        <table class="info-table wide">
          <tr><th>Link</th><th>Status</th><th>Page title</th></tr>
          {rows}
        </table>
        <p class="warn">Reachability only confirms the link works — it does NOT confirm the certificate is authentic or
        belongs to this candidate. Manually open each link and verify the name and issue date match.</p>
        """
    else:
        cert_body = "<p class='muted'>No certificate links provided.</p>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Candidate Report — {escape(candidate_name)}</title>
<style>
  body {{ background:#0a0a0a; color:#e6f5e9; font-family:'Segoe UI',Arial,sans-serif; margin:0; padding:40px 6vw; }}
  .header {{ border-bottom:1px solid {CAND_ACCENT}; padding-bottom:20px; margin-bottom:30px; }}
  .header h1 {{ margin:0; font-size:28px; }}
  .header .meta {{ color:#8fa898; font-size:13px; margin-top:6px; }}
  .section {{ background:rgba(255,255,255,0.03); border:1px solid rgba(0,255,65,0.18); border-radius:10px; padding:24px; margin-bottom:22px; }}
  .section h2 {{ color:{CAND_ACCENT}; font-size:18px; margin-top:0; border-bottom:1px solid rgba(0,255,65,0.18); padding-bottom:10px; }}
  .section h3 {{ font-size:14px; color:#cfe9db; margin-bottom:8px; }}
  .info-table {{ width:100%; border-collapse:collapse; margin-bottom:16px; }}
  .info-table td, .info-table th {{ padding:8px 10px; border-bottom:1px solid rgba(255,255,255,0.06); font-size:14px; text-align:left; vertical-align:top; }}
  .info-table td:first-child {{ color:#8fa898; width:160px; }}
  .info-table.wide td:first-child {{ width:auto; color:inherit; }}
  a {{ color:#57ffe0; text-decoration:none; }}
  a:hover {{ text-decoration:underline; }}
  .chip-row {{ display:flex; flex-wrap:wrap; gap:8px; margin-bottom:10px; }}
  .chip {{ background:rgba(0,255,65,0.08); border:1px solid rgba(0,255,65,0.3); color:#57ffe0; padding:4px 12px; border-radius:14px; font-size:12px; }}
  .repo-row {{ padding:10px 0; border-bottom:1px solid rgba(255,255,255,0.06); font-size:14px; }}
  .stars {{ color:#ffbd2e; font-size:12px; }}
  .muted {{ color:#8fa898; font-size:13px; }}
  .warn {{ color:#ffbd2e; font-size:13px; background:rgba(255,189,46,0.08); padding:10px 14px; border-radius:6px; border:1px solid rgba(255,189,46,0.3); }}
  .ok {{ color:#57ffe0; }}
  .bad {{ color:#ff6b6b; }}
  .footer {{ text-align:center; color:#5c6e61; font-size:12px; margin-top:30px; padding-top:16px; border-top:1px solid rgba(0,255,65,0.15); }}
</style>
</head>
<body>
  <div class="header">
    <h1>Candidate Verification Report — {escape(candidate_name)}</h1>
    <div class="meta">Generated {now} · MR OSINT Candidate Profile Verifier</div>
  </div>

  {section("GitHub Profile", gh_body)}
  {section("Portfolio Website", port_body)}
  {section("Certificate Links", cert_body)}

  <div class="footer">
    Generated by MR OSINT — Harsh Saini / MR CYBER<br>
    cyber.h4rsh@zohomail.in · https://mrcyberharsh.github.io/mrcyber/<br><br>
    This report is based only on information the candidate provided and public data —
    it is a starting point for verification, not a final decision-making tool.
  </div>
</body>
</html>"""
    return html


def cmd_candidate(args):
    print(f"\nGenerating candidate report for: {args.name}")

    github_data, github_err = (None, None)
    if args.github:
        print(f"  Checking GitHub: {args.github} ...")
        github_data, github_err = cand_fetch_github(args.github)

    portfolio_result = None
    if args.portfolio:
        print(f"  Checking portfolio: {args.portfolio} ...")
        portfolio_result = cand_check_url(args.portfolio)

    cert_results = []
    for cert_url in args.cert:
        print(f"  Checking certificate link: {cert_url} ...")
        cert_results.append((cert_url, cand_check_url(cert_url)))

    html = cand_build_html_report(args.name, github_data, github_err, args.portfolio, portfolio_result, cert_results)

    safe_name = re.sub(r"[^a-zA-Z0-9_-]+", "_", args.name).strip("_") or "candidate"
    filename = f"report_{safe_name}_{datetime.now().strftime('%Y%m%d_%H%M')}.html"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\nReport saved: {filename}")
    print("Open it directly in any browser — no server needed.\n")


# ======================================================================
# MAIN
# ======================================================================

def main():
    parser = argparse.ArgumentParser(
        prog="mr_osint_toolkit.py",
        description="MR OSINT — unified toolkit (username / ip / email / phone / scamcheck / candidate). By Harsh Saini — MR CYBER.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_username = sub.add_parser("username", help="Check a username's presence across 20 major platforms")
    p_username.add_argument("username")
    p_username.add_argument("--timeout", type=float, default=6)
    p_username.add_argument("--threads", type=int, default=12)
    p_username.set_defaults(func=cmd_username)

    p_ip = sub.add_parser("ip", help="Look up geolocation/ISP info for an IP address")
    p_ip.add_argument("ip")
    p_ip.set_defaults(func=cmd_ip)

    p_email = sub.add_parser("email", help="Validate an email address and check its domain")
    p_email.add_argument("email")
    p_email.set_defaults(func=cmd_email)

    p_phone = sub.add_parser("phone", help="Validate a phone number and show its metadata")
    p_phone.add_argument("number")
    p_phone.set_defaults(func=cmd_phone)

    p_scam = sub.add_parser("scamcheck", help="Check a website for common scam red flags")
    p_scam.add_argument("target", help="Domain or URL, e.g. example.com or https://example.com")
    p_scam.set_defaults(func=cmd_scamcheck)

    p_cand = sub.add_parser("candidate", help="Generate an HTML candidate verification report")
    p_cand.add_argument("--name", required=True)
    p_cand.add_argument("--github")
    p_cand.add_argument("--portfolio")
    p_cand.add_argument("--cert", action="append", default=[])
    p_cand.set_defaults(func=cmd_candidate)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
