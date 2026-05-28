# Python Login Demos

This folder contains the two CLI versions of the login project:

- `login_vulnerable.py` - intentionally insecure for learning
- `login_secure.py` - fixed version with safer practices

## How to run

From the project root:

```bash
python python/login_vulnerable.py
python python/login_secure.py
```

## What to look for

The vulnerable version demonstrates:

- SQL injection
- plain-text password storage
- weak MD5 hashing
- hardcoded secrets
- verbose error leakage

The secure version fixes those issues with parameterized queries, bcrypt, environment-based config, validation, and safer error handling.
