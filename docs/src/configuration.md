# Configuration

Crabcakes uses a filesystem-based configuration system that stores credentials, policies, and metadata in a configurable directory. This page covers the structure, requirements, and management of configuration files.

## Configuration Directory

### Default Location

By default, Crabcakes looks for configuration in the `./config` directory relative to where the server is started. This can be customized using:

- CLI flag: `--config-dir <PATH>`
- Environment variable: `CRABCAKES_CONFIG_DIR`

### Directory Structure

```text
config/
├── credentials/          # Credential JSON files (one per credential)
│   ├── alice.json
│   └── bob.json
├── policies/            # Policy JSON files (one per policy)
│   ├── admin.json
│   └── read-only.json
└── crabcakes.sqlite3    # SQLite database for metadata
```

**Automatic Creation**: If the configuration directory or its subdirectories don't exist, they will be created automatically when the server starts.

## Credentials

Credentials are stored as individual JSON files in the `credentials/` subdirectory. Each file represents one set of AWS-compatible access credentials.

### Credential File Format

Each credential file must be a valid JSON file with exactly two fields, and `secret_access_key` must be 40 characters in length.

```json
{
  "access_key_id": "alice",
  "secret_access_key": "alicesecret12345678901234567890123456712x"
}
```

### Field Requirements

#### `access_key_id`

- **Type**: String
- **Usage**: Used as the username for authentication and authorization

#### `secret_access_key`

- **Type**: String
- **Length**: **MUST be exactly 40 characters** (AWS standard length)
- **Validation**: Enforced at load time and creation time
- **Critical**: Credentials with invalid secret length will be rejected with an error

### Credential Loading Behavior

- All `.json` files in the `credentials/` directory are loaded at server startup
- Files are processed asynchronously
- Invalid credentials are logged but don't prevent server startup
- If no valid credentials are loaded, the server will start but no authentication will succeed
- Credentials are cached in memory for fast signature verification

### Duplicate Access Key Prevention

**During Startup (File Loading)**:

- If multiple credential files contain the same `access_key_id`, the **first file processed wins**
- A warning is logged when duplicate `access_key_id` values are encountered: *"Duplicate access_key_id found, ignoring this credential file (first credential loaded takes precedence)"*
- Subsequent credential files with the same `access_key_id` are ignored
- Only the first credential loaded will be active

**When Creating Credentials via Web UI**:

- The server explicitly checks if a credential with the same `access_key_id` already exists
- If found, returns HTTP error with message: "Credential with the same identifier already exists"
- Creation is blocked - you must delete the existing credential first

**Best Practice**: Use unique `access_key_id` values and avoid creating multiple credential files with the same identifier.

### Security Considerations

- **Never commit production credentials to git** - Add `config/` to your `.gitignore`
- Secret access keys are stored as `SecretString` in memory to prevent accidental logging
- Credentials cannot use path traversal sequences in access_key_id (`..`, `/`, `\` are blocked)

## Policies

Policies define authorization rules using AWS IAM-compatible policy syntax. Policy files are stored in the `policies/` subdirectory.

See [Policies](policies.md) for more details.

## Configuration Options

### CLI Flags

```bash
crabcakes [OPTIONS]
```

**Server Options**:

- `--host <HOST>` - Listener address (default: `127.0.0.1`)
- `-p, --port <PORT>` - Port number (default: `9000`)
- `-r, --root-dir <PATH>` - Root directory for file storage (default: `./data`)

**Configuration**:

- `-c, --config-dir <PATH>` - Configuration directory (default: `./config`)
- `--region <REGION>` - AWS region name (default: `crabcakes`)

**TLS**:

- `--tls-cert <PATH>` - Path to TLS certificate file
- `--tls-key <PATH>` - Path to TLS private key file

**Authentication**:

- `--oidc-client-id <ID>` - OIDC client ID for OAuth2 authentication (required for admin UI)
- `--oidc-discovery-url <URL>` - OIDC issuer URL (required for admin UI)
- `--frontend-url <URL>` - Frontend URL for OIDC redirect URIs when behind reverse proxy

### Environment Variables

All CLI flags can be set via environment variables:

- `CRABCAKES_LISTENER_ADDRESS` - Listener address
- `CRABCAKES_PORT` - Port number
- `CRABCAKES_ROOT_DIR` - Root directory for files
- `CRABCAKES_CONFIG_DIR` - Configuration directory
- `CRABCAKES_REGION` - AWS region name
- `CRABCAKES_TLS_CERT` - TLS certificate path
- `CRABCAKES_TLS_KEY` - TLS key path
- `CRABCAKES_OIDC_CLIENT_ID` - OIDC client ID
- `CRABCAKES_OIDC_DISCOVERY_URL` - OIDC discovery URL
- `CRABCAKES_FRONTEND_URL` - Frontend URL for reverse proxy

### Examples

**Basic setup**:

```bash
crabcakes --config-dir /etc/crabcakes
```

**Custom host and port**:

```bash
crabcakes --host 0.0.0.0 --port 8080
```

**Using environment variables**:

```bash
export CRABCAKES_CONFIG_DIR=/etc/crabcakes
export CRABCAKES_PORT=8080
export CRABCAKES_OIDC_CLIENT_ID=your-client-id
export CRABCAKES_OIDC_DISCOVERY_URL=https://accounts.google.com
crabcakes
```

**With TLS**:

```bash
crabcakes \
  --tls-cert /path/to/cert.pem \
  --tls-key /path/to/key.pem \
  --frontend-url https://s3.example.com
```

## Database

Crabcakes uses SQLite to store metadata including object tags, OAuth PKCE state, temporary credentials, and bucket website configurations.

**Database Location**: `{config_dir}/crabcakes.sqlite3`

**Features**:

- Automatically created on first startup
- Migrations run automatically on startup
- WAL mode enabled for better concurrency
- Auto-vacuum enabled for disk space management

**For complete database schema and details**, see the [Database Documentation](database.md).

## Reserved Names

The following bucket names are reserved for the admin UI and cannot be created as S3 buckets:

- `admin`
- `api`
- `login`
- `logout`
- `oauth2`
- `.well-known`
- `config`
- `oidc`
- `crabcakes`
- `docs`
- `help`
- `.multipart`

## Best Practices

### Security

1. **Never commit credentials to git**: Add `config/` to `.gitignore`
2. **Use strong secrets**: Generate random 40-character secret access keys
3. **Principle of least privilege**: Grant minimum permissions needed
4. **Test policies**: Use the Policy Troubleshooter before deploying

### Organization

1. **Naming conventions**: Use descriptive names for credentials and policies
2. **One policy per use case**: Create separate policy files for different roles
3. **Document policies**: Use meaningful `Sid` values in policy statements
4. **Regular audits**: Review credentials and policies periodically

### Production Deployment

1. **Use TLS**: Always enable TLS in production with `--tls-cert` and `--tls-key`
2. **Restrict host**: Use `--host 127.0.0.1` or specific IP, not `0.0.0.0`
3. **Configure OIDC**: Set up proper OIDC provider for admin UI authentication
4. **Set frontend URL**: Use `--frontend-url` when behind reverse proxy
5. **Monitor logs**: Use `RUST_LOG` environment variable for logging control

## Troubleshooting

### Credentials not loading

**Symptoms**: Authentication fails, logs show "No credentials loaded"

**Solutions**:

- Verify credential files are in `{config_dir}/credentials/`
- Check files have `.json` extension
- Verify JSON is valid (use `jq` or JSON validator)
- Ensure `secret_access_key` is exactly 40 characters
- Check file permissions (must be readable by server process)

### Policies not taking effect

**Symptoms**: Authorization denied unexpectedly

**Solutions**:

- Verify policy files are in `{config_dir}/policies/`
- Check JSON syntax is valid
- Use Policy Troubleshooter to test evaluation
- Check principal ARN matches credential's `access_key_id`
- Verify resource ARN matches bucket/key being accessed
- Remember: explicit Deny wins over Allow

### Database errors

**Symptoms**: Errors related to SQLite or migrations

**Solutions**:

- Check `{config_dir}` directory is writable
- Verify disk space is available
- Delete `crabcakes.sqlite3*` files and restart (data will be lost)
- Check for file permission issues

### Admin UI not accessible

**Symptoms**: Cannot access `/admin` URL

**Solutions**:

- Verify OIDC is configured (`--oidc-client-id` and `--oidc-discovery-url`)
- Check OIDC discovery URL is correct and accessible
- Verify redirect URI is registered with OIDC provider
- Use `--frontend-url` if behind reverse proxy
- Check browser console for errors
