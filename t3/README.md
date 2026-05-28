# Secure Coding Review Project

Combined documentation for both parts of this project:

- CLI demos in `python/`
- Flask website in `website/`

## Project structure

```text
t3/
├── python/
│   ├── login_vulnerable.py
│   ├── login_secure.py
│   └── README.md
├── website/
│   ├── app.py
│   ├── templates/
│   └── README.md
├── requirements.txt
├── .env.example
└── README.md
```

## One-time setup

```bash
pip install -r requirements.txt
cp .env.example .env
```

## Run the website

```bash
python website/app.py
```

Open these URLs:

- `http://127.0.0.1:5000/`
- `http://127.0.0.1:5000/vulnerable`
- `http://127.0.0.1:5000/secure`

Stop with `Ctrl+C`.

## Run the Python CLI demos

```bash
python python/login_vulnerable.py
python python/login_secure.py
```

## Vulnerability coverage

The vulnerable flow demonstrates:

- SQL injection
- plain-text password storage
- weak MD5 hashing
- hardcoded secrets
- verbose error leakage
- sensitive data logging

The secure flow demonstrates:

- parameterized SQL queries
- bcrypt password hashing
- environment-based configuration
- input validation
- generic error handling

## Optional security scan

```bash
bandit -r python/login_vulnerable.py
```

## Folder-specific docs

- `python/README.md`
- `website/README.md`
