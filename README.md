# ☁️ CloudDocVault

Secure document storage web app built for **AWS** - a cloud-computing mini project that uses **IaaS, PaaS, DBaaS, Storage and Security** services together.

**Developed by Satyam Kanojiya**

## Cloud services used

| Requirement | AWS service | How it is used |
|---|---|---|
| IaaS | **Amazon EC2** | The Elastic Beanstalk environment runs on an EC2 instance |
| PaaS | **AWS Elastic Beanstalk** | Deploys the Flask app (`Procfile` + gunicorn behind nginx) |
| DBaaS | **Amazon RDS (PostgreSQL)** | Users, file metadata and the audit log |
| Storage | **Amazon S3** | Uploaded files, encrypted at rest (SSE-AES256) |
| Security | **IAM + Security Groups** | EC2 role gets S3 access (no keys in code); RDS is private and reachable only from the app |

## Features

- Register / login with hashed passwords (scrypt), CSRF protection, login throttling, secure headers
- Dashboard with stat cards, storage **donut chart**, 14-day **upload chart** and quota bar
- Drag & drop multi-upload, categories, favourites, search and sorting, **rename**, image / PDF / text **preview**
- Download counters, **Download all as ZIP**, **recycle bin** (restore / delete forever)
- **Signed, expiring share links** (1 h / 24 h / 7 d) with optional password
- **Activity log** (audit trail) with CSV export, account page with password change
- **`/status` page**: live health, latency and architecture diagram of every cloud service (`/status.json` too)
- Dark mode

## Run it anywhere - no AWS needed

CloudDocVault works fully **without any cloud account**: with no environment variables it uses a local SQLite file and a local `uploads/` folder. Every feature (dashboard, charts, share links, trash, ZIP export...) works the same.

**Windows:** double-click `run_local.bat`  |  **Linux / Mac:** `bash run_local.sh`

Or manually:

```bash
python -m venv venv
venv\Scripts\activate          # Windows  (Linux/Mac: source venv/bin/activate)
pip install -r requirements-local.txt
python seed_demo.py            # optional: demo account  demo / Demo@12345  with sample files
python app.py                  # open http://localhost:5000
```

With Docker: `docker compose up --build` then open http://localhost:8000

Run the tests: `python tests/test_app.py`

### Free online hosting (optional)

Any host that runs Python/Flask works. Start command: `gunicorn app:application --bind 0.0.0.0:$PORT`.
Set `SECRET_KEY` as an environment variable. Note that many free hosts wipe local files and SQLite data when the app restarts, so use them for demos, not for storing important files. On PythonAnywhere (free plan) point the WSGI file to `from app import application`.

## Deploy on AWS Elastic Beanstalk

1. Create an S3 bucket and an RDS PostgreSQL instance (free tier) in the same region.
2. Zip the project **contents** (so `app.py` and `Procfile` are at the top of the zip; leave out `tests/` and `.git`).
3. Elastic Beanstalk → Create environment → Python 3.12, **Single instance**, upload the zip.
4. Give the EC2 instance profile (`aws-elasticbeanstalk-ec2-role`) S3 permission.
5. Set environment properties: `SECRET_KEY`, `S3_BUCKET`, `AWS_REGION`, `DATABASE_URL` (see `.env.example`).
6. Add the RDS security group to the environment so the app can reach the database.
7. Open the environment URL, then `/health` and `/status` to verify.

> Remember to terminate the environment and delete the RDS instance and S3 bucket when you are done to avoid charges.

## Project structure

```
run_local.bat / run_local.sh   one-click local start
seed_demo.py    creates a demo account with sample data
app.py          Flask application (routes, security, dashboard logic)
db.py           SQLite / PostgreSQL layer with automatic schema migrations
storage.py      S3 or local-disk storage
Procfile        gunicorn start command for Elastic Beanstalk
templates/      Jinja2 pages
static/app.js   Small vanilla-JS helpers (theme, drag & drop)
tests/          End-to-end tests
```
