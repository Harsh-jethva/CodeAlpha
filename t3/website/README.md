# Flask Login Website

This folder contains the web version of the login security demo.

## Files

- `app.py` - Flask application with vulnerable and secure routes
- `templates/` - HTML templates for the site

## How to run

From the project root:

```bash
python website/app.py
```

Then open:

- `http://127.0.0.1:5000/` - home page
- `http://127.0.0.1:5000/vulnerable` - insecure demo
- `http://127.0.0.1:5000/secure` - secure demo

## Demo details

The vulnerable route shows:

- SQL injection
- plain-text password storage
- MD5 hashing
- verbose error messages
- sensitive logging

The secure route uses:

- parameterized queries
- bcrypt hashing
- input validation
- generic error handling
