# Backup & Restore

## Database Location

KRYON stores all data in SQLite at `~/.kryon/kryon.db`.

## Backup

### API Endpoint

```bash
curl -X POST http://localhost:8700/api/v1/admin/backup \
  -H "Authorization: Bearer <admin-token>" \
  -o backup.db
```

### Manual

```bash
cp ~/.kryon/kryon.db ~/backups/kryon_$(date +%Y%m%d).db
```

### SQLite Online Backup

```python
from kryon.memory.store import MemoryStore
from pathlib import Path

store = MemoryStore()
store.backup(Path("~/backups/kryon_backup.db"))
```

## Restore

1. Stop the KRYON server
2. Replace `~/.kryon/kryon.db` with the backup
3. Start the server — migrations will run automatically

## Multi-Tenant Backup

With separate DB isolation, each tenant has its own file at `~/.kryon/tenants/tenant_{id}.db`. Back up the entire `tenants/` directory.
