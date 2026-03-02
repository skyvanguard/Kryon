# User Management

## Roles

| Role | Description | Permissions |
|------|-------------|------------|
| `admin` | Full system access | All operations |
| `analyst` | Security testing | Scans, engagements, reports, knowledge |
| `viewer` | Read-only access | View scans, reports, knowledge |

## Creating Users

### Setup Wizard

```bash
kryon setup
```

### API

```bash
curl -X POST http://localhost:8700/api/v1/admin/users \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"username": "analyst1", "email": "analyst1@example.com", "password": "SecurePass123!", "role": "analyst"}'
```

## Password Requirements

- Minimum 8 characters
- At least 1 uppercase letter
- At least 1 lowercase letter
- At least 1 digit
- At least 1 special character

## Client Isolation

Analysts can only access clients they are assigned to. Admins can assign clients:

```bash
curl -X POST http://localhost:8700/api/v1/admin/users/{user_id}/clients/{client_id} \
  -H "Authorization: Bearer <admin-token>"
```
