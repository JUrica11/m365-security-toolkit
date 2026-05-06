# M365 Security Toolkit for MSPs

Production-ready PowerShell scripts for auditing and hardening Microsoft 365 tenant security.  
Built by an MSP engineer, tested in real client environments.

---

## 🆓 Free Script — Start Here

### [M365-MFA-Audit.ps1](./M365-MFA-Audit.ps1)
Scans every user in your tenant and shows:
- Who has **no MFA** (critical risk)
- Who uses **weak MFA only** (SMS/voice — bypassable)
- Which **admin accounts** are unprotected
- Per-user MFA method breakdown
- Color-coded HTML report + CSV export

```powershell
.\M365-MFA-Audit.ps1
.\M365-MFA-Audit.ps1 -OpenReport   # opens HTML in browser
```

**Example output:**
```
Total users audited :  247
No MFA (CRITICAL)   :   31
Weak MFA only       :   18
Strong MFA          :  198
Admin accounts w/o MFA:   3
```

---

## 💼 Security Hardening Pack — $49

The full pack includes 5 scripts that together give you a complete picture of your tenant's security posture.

### What's included:

| Script | What it does |
|---|---|
| ✅ M365-MFA-Audit *(free above)* | MFA coverage across all users |
| 🔒 M365-Conditional-Access-Audit | Finds CA policy gaps — missing MFA policy, legacy auth not blocked, admin policy missing |
| 👥 M365-Guest-Access-Audit | Stale guests, never-accepted invites, inactive external users |
| 🔑 M365-Admin-Roles-Audit | Every privileged account, admin w/o MFA, guest admins, over-permissioned accounts |
| 🔓 M365-Legacy-Auth-Audit | Which users still use IMAP/POP3/SMTP AUTH — blocks MFA bypass |
| 📊 M365-Security-Score-Report | Pulls Microsoft Secure Score + top improvement actions — client-ready HTML |

### Why MSPs buy this:

- **Onboarding new clients** — run all 5 scripts on day 1, instant security baseline
- **Monthly reporting** — HTML reports go straight to client
- **Compliance prep** — evidence for Cyber Essentials, ISO 27001, SOC 2 discussions
- **Upselling** — every finding is a billable remediation project

👉 **[Buy the Security Hardening Pack — $49](https://gumroad.com/YOUR_LINK)**

---

## ✅ Requirements

- PowerShell 7+ ([download](https://aka.ms/powershell))
- Microsoft.Graph module

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

**Minimum roles required:**
- Security Reader + Reports Reader (for audit scripts)
- Global Reader (for full access)

---

## 💬 Questions?

Open an issue on GitHub. PRs welcome.

---

*Not affiliated with Microsoft Corporation. These are independent tools.*
