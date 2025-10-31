# Policies

## Policy File Format

Policies follow standard AWS IAM policy format:

```json
{
    "Version": "2012-10-17",
    "Id": "S3BucketPolicy",
    "Statement": [
        {
            "Sid": "AllowS3All",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam:::user/testuser"
            },
            "Action": [
                "s3:*"
            ],
            "Resource": "arn:aws:s3:::bucket1/testuser/*"
        }
    ]
}
```

## Policy Components

### Version

Standard AWS IAM policy version: `"2012-10-17"`

### Statement Array

Each policy contains one or more statements with the following fields:

**Sid** (optional)

- Statement identifier for documentation purposes

**Effect** (required)

- `"Allow"` - Grants permission
- `"Deny"` - Explicitly denies permission (takes precedence over `Allow`)

**Principal** (required)

- Specifies who the policy applies to
- AWS user: `{"AWS": "arn:aws:iam:::user/username"}`
- Wildcard (anonymous): `"*"`

**Action** (required)

- S3 action or actions to allow/deny
- Single action: `"s3:GetObject"`
- Multiple actions: `["s3:GetObject", "s3:PutObject"]`
- Wildcard: `"s3:*"`

**Resource** (required)

- S3 resource ARN or ARNs
- Specific object: `"arn:aws:s3:::bucket/key"`
- Bucket objects: `"arn:aws:s3:::bucket/*"`
- Multiple resources: `["arn:aws:s3:::bucket1", "arn:aws:s3:::bucket1/*"]`
- Wildcard: `"*"`

### Supported S3 Actions

Crabcakes supports the following S3 actions in policies:

**Object Operations**:

- `s3:GetObject` - Read objects
- `s3:PutObject` - Write objects
- `s3:DeleteObject` - Delete objects
- `s3:GetObjectTagging` - Read object tags
- `s3:PutObjectTagging` - Write object tags
- `s3:DeleteObjectTagging` - Delete object tags
- `s3:GetObjectAttributes` - Read object metadata

**Bucket Operations**:

- `s3:ListBucket` - List bucket contents
- `s3:CreateBucket` - Create new buckets
- `s3:DeleteBucket` - Delete buckets
- `s3:HeadBucket` - Check bucket existence
- `s3:GetBucketLocation` - Get bucket region
- `s3:ListAllMyBuckets` - List all buckets
- `s3:GetBucketWebsite` - Get website configuration
- `s3:PutBucketWebsite` - Set website configuration
- `s3:DeleteBucketWebsite` - Delete website configuration

**Multipart Upload Operations**:

- `s3:AbortMultipartUpload` - Cancel multipart upload
- `s3:ListBucketMultipartUploads` - List in-progress uploads
- `s3:ListMultipartUploadParts` - List parts of an upload

**Wildcards**:

- `s3:*` - All S3 actions

## Policy Name Validation

Policy filenames must meet the following requirements:

- **Pattern**: `^[a-zA-Z0-9]{1}[a-zA-Z0-9-_]*[a-zA-Z0-9]{1}$`
- Must start and end with alphanumeric characters
- Can contain letters, numbers, hyphens (`-`), and underscores (`_`)
- Minimum 2 characters
- Cannot contain `..`, `/`, or `\` (path traversal protection)

**Valid examples**: `admin-policy`, `read_only`, `testUser123`

**Invalid examples**: `-admin`, `policy-`, `a`, `../etc/passwd`

## Policy Evaluation

Crabcakes uses the `iam-rs` library for AWS-compatible policy evaluation:

- **Default deny**: All requests denied unless explicitly allowed
- **Explicit deny wins**: Deny statements override Allow statements
- **Evaluation caching**: Results cached for 5 minutes using SHA256 hash of request
- **Cache invalidation**: Cleared when policies are added, updated, or deleted
- **Wildcard principals**: Supports anonymous access with `"Principal": "*"`

## Policy Loading Behavior

- All `.json` files in the `policies/` directory are loaded at server startup
- Invalid policies are logged and skipped
- Policies can be hot-reloaded via the admin UI
- If a policy file is removed from disk, it's removed from memory on next reload

## Example Policies

**Allow all operations for a specific user**:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam:::user/alice"
            },
            "Action": "s3:*",
            "Resource": "*"
        }
    ]
}
```

**Read-only access to a specific bucket**:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam:::user/bob"
            },
            "Action": [
                "s3:GetObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::public",
                "arn:aws:s3:::public/*"
            ]
        }
    ]
}
```

**User-specific prefix access**:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam:::user/charlie"
            },
            "Action": "s3:*",
            "Resource": "arn:aws:s3:::shared/charlie/*"
        }
    ]
}
```

## Web-Based Policy Management

Crabcakes provides web-based tools for managing and troubleshooting policies. These tools are available in the admin UI at `/admin` (requires OIDC authentication).

### Policy Editor

**Access**: Navigate to `/admin/policies` in your browser after authenticating.

The Policy Editor provides a full-featured interface for managing IAM policies:

**Operations**:

- **List Policies**: View all loaded policies with their details
- **Create Policy**: Form-based policy creation with JSON editor and syntax highlighting
- **Edit Policy**: Modify existing policy JSON with validation
- **View Policy**: See policy details and permissions breakdown
- **Delete Policy**: Remove policies from the system

**How to Use**:

1. Log in to the admin UI at `/admin` using OIDC authentication
2. Click "Policies" in the navigation menu
3. Use the interface to:
   - View the list of all policies
   - Click "New Policy" to create a policy
   - Click "Edit" next to a policy to modify it
   - Click "View" to see detailed permissions
   - Click "Delete" to remove a policy

**Editor Features**:

- JSON syntax highlighting using Prism.js
- Real-time validation before saving
- Principal permissions breakdown view
- Automatic policy cache refresh after changes
- Direct filesystem integration (changes persist to `policies/` directory)

## Policy Troubleshooter

**Access**: Navigate to `/admin/policy_troubleshooter` in your browser after authenticating.

The Policy Troubleshooter helps debug authorization issues by simulating policy evaluation without making actual S3 requests.

**How to Use**:

1. Log in to the admin UI at `/admin`
2. Click "Policy Troubleshooter" in the navigation menu
3. Fill in the evaluation form:
   - **User**: Principal username (e.g., "alice")
   - **Action**: S3 action from dropdown (e.g., "s3:GetObject")
   - **Bucket**: Bucket name
   - **Key**: Object key (optional, for object-level actions)
   - **Policy Name**: Specific policy to test (optional, tests all policies if empty)
4. Click "Test Policy" to see the result

**Output**:

- **Decision**: Allow, Deny, or NotApplicable
- **Matched Statements**: Which policy statements applied
- **Evaluation Context**: Detailed information about the evaluation

**Use Cases**:

- Debug why a user can't access a resource
- Verify policy changes before deploying to production
- Understand which policies are granting/denying access
- Test new policies before creating credentials

**Example**:

To test if user "alice" can read `bucket1/test.txt`:

- User: `alice`
- Action: `s3:GetObject`
- Bucket: `bucket1`
- Key: `test.txt`

The troubleshooter will show whether the request would be allowed based on loaded policies and which policy statements matched.
