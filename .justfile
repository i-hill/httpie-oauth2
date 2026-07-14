# List available recipes
default:
    @just --list

# Validate README.rst renders cleanly
lint-readme:
    uv run --no-project --with docutils python -m docutils --halt=warning README.rst /dev/null

# Deploy the plugin module into the Homebrew httpie plugins environment
install:
    cp httpie_oauth2.py ~/.config/httpie/plugins/lib/python3.14/site-packages/httpie_oauth2.py
