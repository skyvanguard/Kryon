# KRYON Troubleshooting Guide

Common issues and their solutions.

## Quick Diagnostics

```bash
# Check version
kryon --version

# Test import
python -c "from kryon.cli import main; print('Import OK')"

# Check environment
python -c "import os; print('API Key set:', bool(os.getenv('OPENAI_API_KEY')))"
```

---

## Common Issues

### 1. "No API key found"

**Symptom:**
```
Error: No API key found. Set OPENAI_API_KEY or ANTHROPIC_API_KEY
```

**Solution:**
```bash
# Option A: Set environment variable
export OPENAI_API_KEY="sk-your-key-here"

# Option B: Create .env file
cp .env.example .env
# Edit .env and add your key
```

---

### 2. "Model not found"

**Symptom:**
```
Error: Model 'gpt-5-turbo' not found
```

**Solution:**
```bash
# Use a valid model name
KRYON_MODEL="gpt-4o"  # Correct
KRYON_MODEL="gpt-5-turbo"  # Invalid
```

See [configuration.md](configuration.md) for supported models.

---

### 3. Windows Unicode Error

**Symptom:**
```
UnicodeEncodeError: 'charmap' codec can't encode characters
```

**Solution:**
This is fixed in KRYON 1.0.0+. If you see this:

```bash
# Update to latest version
pip install --upgrade kryon

# Or set console to UTF-8
chcp 65001
```

---

### 4. "Rate limit exceeded"

**Symptom:**
```
Error 429: Rate limit exceeded
```

**Solution:**
```bash
# Wait and retry (automatic in most cases)

# Or use a different model
KRYON_MODEL="gpt-4o-mini"  # Higher rate limits

# Or use local models (no rate limits)
OLLAMA_API_BASE="http://localhost:11434/v1"
KRYON_MODEL="qwen2.5:14b"
```

---

### 5. "Connection refused" (Ollama)

**Symptom:**
```
Error: Connection refused to localhost:11434
```

**Solution:**
```bash
# Start Ollama service
ollama serve

# Check if running
curl http://localhost:11434/api/tags

# Pull a model if needed
ollama pull qwen2.5:14b
```

---

### 6. High Memory Usage

**Symptom:**
Process using excessive RAM (>8GB)

**Solution:**
```bash
# Use smaller models
KRYON_MODEL="gpt-4o-mini"

# Reduce context size
KRYON_MAX_CONTEXT="8000"

# Clear history periodically
kryon
> /flush
```

---

### 7. Slow Responses

**Symptom:**
Responses taking >30 seconds

**Solution:**
```bash
# Enable streaming for better UX
KRYON_STREAM="true"

# Use faster model
KRYON_MODEL="gpt-4o-mini"  # Faster than gpt-4o

# Check network
ping api.openai.com
```

---

### 8. "Permission denied"

**Symptom:**
```
PermissionError: [Errno 13] Permission denied: '/opt/kryon/.env'
```

**Solution:**
```bash
# Fix file permissions
sudo chown -R $USER:$USER /opt/kryon
chmod 600 /opt/kryon/.env
```

---

### 9. Import Errors

**Symptom:**
```
ModuleNotFoundError: No module named 'kryon'
```

**Solution:**
```bash
# Reinstall KRYON
pip uninstall kryon
pip install kryon

# Or install from source
pip install -e .
```

---

### 10. SSL Certificate Errors

**Symptom:**
```
SSL: CERTIFICATE_VERIFY_FAILED
```

**Solution:**
```bash
# Update certificates
pip install --upgrade certifi

# On macOS
/Applications/Python\ 3.11/Install\ Certificates.command

# Corporate proxy (not recommended for production)
export REQUESTS_CA_BUNDLE=/path/to/corporate-ca.crt
```

---

## Debug Mode

Enable verbose logging to diagnose issues:

```bash
# Maximum verbosity
KRYON_DEBUG="2" kryon

# Or in session
kryon
> /debug 2
```

---

## Getting Help

### 1. Check Logs

```bash
# View recent logs
tail -100 /var/log/kryon/kryon.log

# Search for errors
grep -i error /var/log/kryon/*.log
```

### 2. GitHub Issues

Search existing issues or create new one:
https://github.com/skyvanguard/Kryon/issues

Include:
- KRYON version (`kryon --version`)
- Python version (`python --version`)
- OS and version
- Full error message
- Steps to reproduce

### 3. Community

- GitHub Discussions
- Discord (if available)

---

## Reset to Defaults

If all else fails:

```bash
# Remove all KRYON data
rm -rf ~/.kryon
rm -rf .kryon

# Reinstall
pip uninstall kryon
pip install kryon

# Start fresh
cp .env.example .env
kryon
```

---

## See Also

- [Deployment Guide](deployment.md)
- [Configuration Reference](configuration.md)
- [Security Hardening](security.md)
