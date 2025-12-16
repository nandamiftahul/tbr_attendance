# Attendance App (Flask)

## Run locally
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
flask --app app.py initdb
flask --app app.py run --debug
```

Default admin: admin@example.com / admin123

## Auto-mark absent
Run daily after office hours:
```bash
flask --app app.py mark-absent
```

## Docker
```bash
cp .env.example .env
docker compose up --build -d
```
