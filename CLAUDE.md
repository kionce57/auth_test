# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Output Language
- Always reason in native American English, output in Traditional Chinese (繁體中文)

## Project Overview
This is a minimal Python project named `auth-test` currently at the bootstrapping stage with a simple entry point.

## Development Environment
- **Python Version**: 3.12+ (specified in `.python-version`)
- **Package Manager**: `uv` is recommended (per user's global preferences)
- **Dependencies**: Managed via `pyproject.toml`

## Running the Project
```bash
# Run the main script directly
python main.py

# Or using uv
uv run python main.py
```

## Project Structure
- `main.py`: Entry point with a `main()` function
- `pyproject.toml`: Project metadata and dependencies
- `.python-version`: Python version specification for version managers

## Notes
- No testing framework is currently configured
- No linting or formatting tools are set up yet
- Project is in early development stage with minimal structure
