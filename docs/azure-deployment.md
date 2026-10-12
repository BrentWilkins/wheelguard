# Private Azure deployment

Wheelguard's Azure runtime uses the same FastAPI entrypoint as the local container. Setting `WHEELGUARD_DATABASE_URL`
selects PostgreSQL metadata; setting `WHEELGUARD_AZURE_STORAGE_ACCOUNT_URL` selects Azure Blob artifact storage. Both
services authenticate with the Container App's managed identity.

The Azure Government example initially uses private HTTP with administration disabled, matching environments where a
certificate is not available during bootstrap. Upgrade by supplying the Key Vault certificate and Entra secret URLs and
setting `enable_tls` and `enable_entra_admin` to true; no application data is moved.

Set `GL_HOST` and `GITLAB_PROJECT_PATH` explicitly, then run
`scripts/bootstrap-azure-deployment-identity.sh` while logged into Azure Government and GitLab to create or reuse the
Entra application and service principal:

```shell
export GL_HOST=gitlab.example.com
export GITLAB_PROJECT_PATH=group/wheelguard
scripts/bootstrap-azure-deployment-identity.sh
```

Then run `scripts/configure-azure-deployment-certificate.sh` to generate a
short-lived local private key, append only its public certificate to the Entra application, and save the combined private
key and certificate as the protected GitLab file variable `AZURE_CLIENT_CERTIFICATE`. Temporary certificate files are
created with mode `0600` and removed before the script exits. The scripts leave deployment disabled until Terraform
outputs have also been configured.

The Azure Government root example creates a dedicated resource group, Container Apps subnet, PostgreSQL delegated
subnet, private-endpoint subnet, and sovereign-cloud PostgreSQL/ACR private DNS zones in an existing VNet. Copy
`terraform.tfvars.example` to an ignored `terraform.tfvars`, choose unused CIDRs, and initialize the declared `azurerm`
backend with the organization's remote-state resource group, storage account, and container.

The first apply uses `deploy_workloads=false` and creates the registry and backing services only. After CI pushes the
first image, set its digest as `image` and change `deploy_workloads=true`; the second apply creates the Container App and
jobs. This avoids placeholder containers and does not move data.

The schema job prefers PostgreSQL's object-ID principal function. Azure environments with an older `pgaadauth` version
fall back to a Microsoft Graph lookup by application name. The module attaches the schema identity to the PostgreSQL
server but deliberately does not give routine Terraform automation authority to modify tenant-wide Graph grants. A
tenant administrator grants only `Application.Read.All` once, after the first infrastructure apply:

```shell
scripts/grant-postgres-graph-access.sh \
  --cloud AzureUSGovernment \
  --tenant-id "${AZURE_TENANT_ID}" \
  --principal-id "$(terraform -chdir=infra/examples/azure-government \
    output -raw schema_identity_principal_id)"
```

The script is intended for review and execution by a Privileged Role Administrator or Global Administrator. It verifies
the cloud, tenant, target identity, requested role, existing assignment, and completed grant. It discovers the
sovereign-cloud Graph endpoint, is idempotent, creates no credentials, and grants no write permission. Environments that
expose `pgaadauth_create_principal_with_oid` do not need this grant.

Package reads are credential-free by default because Container Apps ingress and DNS are private to the VPN VNet. Set
the Terraform input `managed_token_auth_enabled=true` when individually revocable repository credentials should also be
required; the module configures `WHEELGUARD_MANAGED_TOKEN_AUTH_ENABLED` in the application.
The administrator paths use Container Apps Microsoft Entra authentication restricted to configured administrator
groups, while uploads require a short-lived GitLab CI ID token with audience `wheelguard-publisher`, an allowed
`project_path`, and `ref_protected=true`.
Set `publisher_oidc_projects` to explicit paths for least privilege, or to `["*"]` when every project issued by the
configured GitLab instance may publish. The wildcard changes only project authorization; signature, issuer, audience,
expiry, and protected-ref validation remain mandatory.

When tenant administration is temporarily unavailable, `WHEELGUARD_ADMIN_TOKEN` enables a separate HTTP Basic
credential for `/admin`; `WHEELGUARD_ADMIN_TOKEN_ACTOR` selects the identity recorded in the audit log. Use a random
value of at least 32 characters, store it in a versioned Key Vault secret, set `admin_token_key_vault_secret_url`, and
require TLS before enabling it. When a shared vault is used, populate `key_vault_secret_resource_ids` so the application
can read only its certificate and administrator-token secrets. This credential does not replace PostgreSQL
managed-identity authentication and must not reuse `WHEELGUARD_AUTH_TOKEN`. Remove the temporary token settings after
Entra administration is enabled.

Legacy PostgreSQL servers may require a tenant administrator to grant Microsoft Graph access before the normal
application database principal can be created. `temporary_schema_runtime_enabled=true` is an explicit break-glass
bridge that runs the application and advisory job with the schema identity; it also grants that identity Blob access.
Disable it immediately after the schema job creates the normal application principal.

After the schema job and application are running, tokens may be prepared before enabling enforcement. Issue a user's
credential from the application container; the command prints the credential once and PostgreSQL stores only its digest:

```shell
az containerapp exec \
  --resource-group wheelguard-rg \
  --name wheelguard \
  --command "wheelguard token create developer --actor administrator@example.com"
```

The user stores it with uv and uses the private Simple API as the default index:

```shell
uv auth login packages.example.com --username developer
```

Use `wheelguard token list` and `wheelguard token revoke <name> --actor <administrator>` through the same
`az containerapp exec` path. Token creation and revocation are recorded in the append-only policy audit log. A revoked
name can be issued again for rotation.

An approved GitLab publishing job configures:

```yaml
id_tokens:
  WHEELGUARD_PUBLISH_TOKEN:
    aud: wheelguard-publisher
script:
  - UV_PUBLISH_TOKEN="$WHEELGUARD_PUBLISH_TOKEN" uv publish --publish-url https://pypi.example.com/upload/
```

Use the reusable module in `infra/modules/azure` from a private Terragrunt live configuration. Keep subscription IDs,
network IDs, the real hostname, certificate URL, Entra application ID, and approved internal GitLab paths in that private
configuration. The checked-in Azure Government example contains inputs only.

CI always enforces Terraform formatting. Set `WHEELGUARD_TERRAFORM_VALIDATE=true` only on runners that can reach a
Terraform provider registry or an organization-configured provider mirror; provider initialization requires that access.
Container builds use an ACR quick build through a pinned Azure CLI installed into the pinned CI image, so the GitLab
runner does not need Microsoft Container Registry access or a privileged Docker or Podman service. The deployment
identity receives both push and ACR Tasks permissions.

Configure these GitLab project CI/CD variables before enabling container builds and deployment. Set
`WHEELGUARD_AZURE_DEPLOY_ENABLED=true` only after the remaining values and certificate credential are ready; Azure
jobs are omitted from pipelines until then.

The opt-in [`ci/azure-deploy.gitlab-ci.yml`](../ci/azure-deploy.gitlab-ci.yml)
template contains the build and manual deployment jobs. Include it from a
private GitLab pipeline only after reviewing it and configuring the protected
variables below.

- `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, and `AZURE_SUBSCRIPTION_ID` identify the certificate-authenticated deployment
  principal and target subscription. `AZURE_CLOUD_NAME` defaults to `AzureUSGovernment` and can be overridden. Do not
  use `AZURE_CLOUD` for this value; Azure SDKs reserve that environment variable for enum names such as
  `AZURE_US_GOVERNMENT`.
- `AZURE_CLIENT_CERTIFICATE` is a protected file variable containing the PEM private key and certificate. CI validates
  the generated file and restricts it to mode `0600`; its contents must never be printed or committed.
- `WHEELGUARD_ACR_NAME`, `WHEELGUARD_ACR_SERVER`, and `WHEELGUARD_IMAGE` identify the registry and repository. For
  example, the image value is `<registry-server>/wheelguard` without a tag.
- `WHEELGUARD_RESOURCE_GROUP`, `WHEELGUARD_SCHEMA_JOB`, `WHEELGUARD_REFRESH_JOB`, `WHEELGUARD_CONTAINER_APP`, and
  `WHEELGUARD_APPLICATION_URL` select the deployed resources. Terraform module outputs provide the generated names where
  applicable.

The deployment certificate defaults to 365 days. Rotate it before expiration by rerunning
`scripts/configure-azure-deployment-certificate.sh`; the script appends the new public certificate and replaces the
protected GitLab file variable while retaining the prior Entra certificate for overlap. Run and verify a container job,
then remove the old certificate with `az ad app credential delete --id <application-id> --key-id <old-key-id>`. Never
delete the old credential before the replacement pipeline succeeds. The service principal and its existing
least-privilege role assignments do not change during rotation.

Certificate authentication removes any need for Entra to retrieve metadata from the private GitLab instance. The
runner still requires outbound TLS access to Azure Government identity, Resource Manager, and ACR endpoints; preserve
the existing firewall and `NO_PROXY` configuration. ACR Tasks uploads build contexts through signed Azure Government
Blob URLs, so `.blob.core.usgovcloudapi.net` must also bypass TLS-intercepting proxies. No public GitLab ingress is
required.

Microsoft-hosted ACR Tasks agents reach the registry over its public service endpoint. The module enables that endpoint
with `default_action = "Deny"` and permits only Azure trusted services and Tasks; application image pulls continue through
the ACR private endpoint. Azure Government quick-build agents may also require their narrow regional egress CIDRs in
`acr_task_agent_ip_ranges`; do not use a catch-all. This does not add public access to GitLab or Wheelguard and does not
broaden deployment roles. Prefer a VNet-integrated ACR agent pool when builds become frequent enough to justify its
dedicated subnet and ongoing cost.

The container job obtains the immutable image digest from the completed ACR Tasks management-plane run result. It does
not query the registry data plane from the untrusted runner subnet, so the registry firewall does not need a runner IP
exception.

Before a new application revision, `scripts/run-azure-schema-upgrade.sh` starts the `wheelguard-schema-upgrade`
Container Apps Job and waits for it to succeed.
Despite the conventional name, schema migrations do not move old D1/R2 data. The initial deployment creates empty tables;
later jobs apply structural upgrades only. No Cloudflare data import is included or required.

Allow outbound HTTPS through the organization firewall to PyPI, `files.pythonhosted.org`, OSV, the GitLab issuer/JWKS
endpoint, and the Azure identity/control-plane endpoints required by the selected cloud. The package hostname resolves to
the internal Container Apps address through private DNS and should not resolve for clients outside the VPN.

## Private GitLab working copy

Import the public repository into a private GitLab project, then configure remotes locally:

```shell
git remote rename origin upstream
git remote add origin git@gitlab.example.com:group/wheelguard.git
git fetch --all --prune
```

Keep private deployment configuration on the GitLab main branch. For an upstream contribution, branch from
`upstream/main`, cherry-pick only generic commits, verify the diff contains no internal values, and open a GitHub pull
request after organizational approval. A cross-host GitLab import is a private mirror, not a GitHub fork-network member.
