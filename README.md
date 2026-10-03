<div align="center">

# CloudDocVault

**Secure document storage web application, built on public-cloud services and runnable anywhere.**

![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-000000?logo=flask&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-EC2%20%7C%20Elastic%20Beanstalk%20%7C%20RDS%20%7C%20S3-FF9900?logo=amazonaws&logoColor=white)
![Database](https://img.shields.io/badge/Database-PostgreSQL%20%7C%20SQLite-336791?logo=postgresql&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

Developed by **[Satyam Kanojiya](https://github.com/Satyamkanojiya666)**

</div>

---

## Table of contents

1. [Overview](#overview)
2. [Features](#features)
3. [Architecture](#architecture)
4. [Cloud services used](#cloud-services-used)
5. [Quick start (no AWS needed)](#quick-start-no-aws-needed)
6. [Configuration](#configuration)
7. [Deploying on AWS](#deploying-on-aws)
8. [Security](#security)
9. [Testing](#testing)
10. [Project structure](#project-structure)
11. [Roadmap](#roadmap)
12. [Author](#author)

---

## Overview

CloudDocVault lets users upload, organise, preview and securely share documents through a clean web dashboard.
It was built as a **cloud-computing mini project** to demonstrate how **IaaS, PaaS, DBaaS, Storage-as-a-Service and Security services** work together in one real application.

The same code runs in two modes, selected only by environment variables:

| Mode | Database | File storage | Use case |
|---|---|---|---|
| **Local** (default) | SQLite | Local `uploads/` folder | Development, demos, offline use |
| **Cloud** | Amazon RDS (PostgreSQL) | Amazon S3 (encrypted) | Production-style deployment on AWS |

## Features

**Dashboard and insights**
- Stat cards: files, storage used, favourites, downloads, share links, trash
- Storage **donut chart** by file type and a **14-day upload chart**
- Per-user storage quota with progress bar
- Light and dark theme

**File management**
- Drag-and-drop **multi-file upload** (PDF, DOCX, TXT, XLSX, CSV, PPTX, PNG, JPG; 5 MB per file)
- Categories, favourites, search and sorting (newest, name, size, most downloaded)
- **Rename**, **preview** (images, PDF, text), download counters
- **Download all as ZIP**
- **Recycle bin**: restore or delete permanently

**Sharing and security**
- **Signed, expiring share links** (1 hour, 24 hours or 7 days) with an optional password
- **Audit log** of every action, with **CSV export**
- Account page with password change
- Login throttling, CSRF protection, secure HTTP headers

**Operations**
- `/status` page with live health, latency and an architecture diagram of every cloud service
- `/status.json` and `/health` endpoints for monitoring

## Architecture

```mermaid
flowchart LR
    U["User (browser / mobile)"] --> A["Elastic Beanstalk<br/>EC2 instance: nginx + gunicorn + Flask"]
    A --> D[("Amazon RDS<br/>PostgreSQL")]
    A --> S[("Amazon S3<br/>encrypted files")]
    IAM["IAM role"] -. "grants S3 access" .-> A
    SG["Security Groups"] -. "RDS reachable only from the app" .-> D
```

## Cloud services used

| Requirement | AWS service | Role in the project |
|---|---|---|
| IaaS | **Amazon EC2** | Virtual server that runs the application |
| PaaS | **AWS Elastic Beanstalk** | Deploys and manages the Flask app (`Procfile`, gunicorn, nginx) |
| DBaaS | **Amazon RDS (PostgreSQL)** | Users, file metadata and the audit log |
| Storage | **Amazon S3** | Uploaded files, encrypted at rest (SSE-AES256) |
| Security | **IAM and Security Groups** | The EC2 role grants S3 access (no keys in code); RDS is private |

## Quick start (no AWS needed)

Requirements: **Python 3.10 or newer**.

**One click:** run `run_local.bat` (Windows) or `bash run_local.sh` (Linux / macOS).

**Manually:**

```bash
git clone https://github.com/Satyamkanojiya666/CloudDocVault.git
cd CloudDocVault

python -m venv venv
venv\Scripts\activate            # Windows   (Linux/macOS: source venv/bin/activate)
pip install -r requirements-local.txt

python seed_demo.py              # optional: creates demo / Demo@12345 with sample files
python app.py                    # open http://localhost:5000
```

**Docker:**

```bash
docker compose up --build        # open http://localhost:8000
```

**Termux (Android):** `pkg install python git`, then follow the manual steps above.

## Configuration

All settings are environment variables; copy `.env.example` as a starting point. Nothing is hard-coded.

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | development value | Signs sessions and share links. **Set a long random value in production.** |
| `DATABASE_URL` | local SQLite file | `postgresql://USER:PASSWORD@HOST:5432/DBNAME` to use PostgreSQL / RDS |
| `S3_BUCKET` | empty (local disk) | S3 bucket name; when set, files are stored in S3 |
| `AWS_REGION` | `ap-south-1` | Region of the S3 bucket |
| `QUOTA_MB` | `25` | Storage quota per user |
| `SESSION_COOKIE_SECURE` | `0` | Set to `1` when serving over HTTPS |
| `PORT` | `5000` | Port for `python app.py` |

## Deploying on AWS

1. Create an **S3 bucket** and an **RDS PostgreSQL** instance (free tier) in the same region.
2. Zip the project **contents** so that `app.py` and `Procfile` sit at the top level of the archive (exclude `tests/` and `.git`).
3. In Elastic Beanstalk create a **Python 3.12** environment, **single instance**, and upload the zip.
4. Attach S3 permissions to the instance profile `aws-elasticbeanstalk-ec2-role`.
5. Set the environment properties `SECRET_KEY`, `S3_BUCKET`, `AWS_REGION` and `DATABASE_URL`.
6. Add the RDS security group to the environment so the app can reach the database.
7. Open the environment URL, then check `/health` and `/status`.

> Remember to terminate the environment and delete the RDS instance and S3 bucket when finished, to avoid charges.

## Security

- Passwords hashed with **scrypt**; never stored in plain text
- **CSRF tokens** on every form, **HttpOnly** and **SameSite** session cookies
- **Login throttling**: 5 failed attempts lock the account/IP pair for 5 minutes
- Strict security headers: `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`
- File type allow-list, per-file size limit and per-user quota
- Share links are **signed and time-limited**; optional passwords are verified with a keyed hash and are never stored
- Complete **audit trail** with CSV export (formula-injection safe)
- AWS credentials are never in code: S3 access comes from the **IAM role**

## Testing

End-to-end tests run on SQLite and a temporary folder, so no AWS account is required:

```bash
python tests/test_app.py
```

They cover authentication, upload limits and quota, preview, share links (open, protected, expired, tampered), trash and restore, ZIP and CSV export, access isolation between users, and database migration from older versions.

## Project structure

```
CloudDocVault/
├── app.py                 Flask application: routes, security, dashboard logic
├── db.py                  SQLite / PostgreSQL layer with automatic schema migrations
├── storage.py             S3 or local-disk storage
├── seed_demo.py           Creates a demo account with sample data
├── Procfile               gunicorn start command for Elastic Beanstalk
├── Dockerfile, docker-compose.yml
├── run_local.bat / .sh    One-click local start
├── requirements.txt       Full dependencies (AWS deployment)
├── requirements-local.txt Minimal dependencies (local use)
├── templates/             Jinja2 pages
├── static/app.js          Small vanilla-JS helpers (theme, drag and drop)
└── tests/test_app.py      End-to-end tests
```

## Roadmap

- HTTPS with a load balancer and an ACM certificate
- Automatic purge of old trash items
- Folder support and bulk actions
- Email notifications for share links

## Author

**Satyam Kanojiya**
GitHub: [@Satyamkanojiya666](https://github.com/Satyamkanojiya666)

If you find this project useful, consider giving it a star.
