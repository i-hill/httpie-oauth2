==============================================
OAuth 2.0 Client Credentials Plugin for HTTPie
==============================================

An `HTTPie <https://httpie.io/>`_ auth plugin that fetches a bearer token
using the OAuth 2.0 Client Credentials flow and attaches it to your request
as an ``Authorization: Bearer`` header.

Forked from `bdemers/httpie-oauth2 <https://github.com/bdemers/httpie-oauth2>`_
by Brian Demers.

Installation
============

Install from a clone of this repo into HTTPie's plugin environment:

::

   httpie cli plugins install /path/to/httpie-oauth2

Alternatively, ``pip install .`` into the same Python environment that
HTTPie runs from.

Usage
=====

::

   http -A oauth2 \
        --client-id "$CLIENT_ID" \
        --client-secret "$CLIENT_SECRET" \
        --issuer-uri "https://issuer.example.com/auth/token" \
        --scope "your-scope" \
        https://api.example.com/your-url

Every option can also be supplied via an environment variable, so secrets
can stay out of your shell history:

===================  ===============================  =========================
Option               Environment variable             Meaning
===================  ===============================  =========================
``--client-id``      ``HTTPIE_OAUTH2_CLIENT_ID``      OAuth 2.0 client ID
``--client-secret``  ``HTTPIE_OAUTH2_CLIENT_SECRET``  OAuth 2.0 client secret
``--issuer-uri``     ``HTTPIE_OAUTH2_ISSUER``         Token endpoint URL
``--scope``          ``HTTPIE_OAUTH2_SCOPE``          Scope(s) to request
===================  ===============================  =========================

Command-line options take precedence over environment variables.

Errors
======

Token endpoint problems are reported as a short message rather than a
Python traceback:

- a wrong or dead token URL (e.g. an HTML 404 page) reports the HTTP
  status, content type, and a snippet of the body;
- OAuth 2.0 error responses (``invalid_client``, ``invalid_scope``, ...)
  report the server's error description;
- missing ``--issuer-uri`` or ``--client-id`` is caught before any
  request is made.
