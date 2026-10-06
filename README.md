# Security Advisories

Independent vulnerability advisories. Each advisory contains an
affected-versions table, vulnerability details, PoC with dynamic
verification output, impact analysis, and remediation guidance.

| Severity | Advisory | Project |
|---|---|---|
| Critical (9.8) | [ConvertX v0.19.0 Hardcoded Default JWT Secret — Full Authentication Bypass](ConvertX_Hardcoded_Default_JWT_Secret_Auth_Bypass.md) | C4illin/ConvertX |
| Critical (9.8) | [Mobile-MCP Streamable HTTP Server Missing Authentication Exposes Full Mobile-Device Control](MobileMCP_Streamable_HTTP_No_Authentication_Device_Control_Exposure.md) | mobile-next/mobile-mcp |
| Critical (9.8) | [open-wearables Documented Default Administrator Credentials — Unauthenticated Platform Takeover](OpenWearables_Default_Admin_Credentials_Takeover.md) | the-momentum/open-wearables |
| Critical (9.8) | [Zilla http-filesystem Binding Unauthenticated Path Traversal](Zilla_Http_Filesystem_Binding_Path_Traversal.md) | aklivity/zilla |
| Critical (9.8) | [Arbitrary File Read/Write/Delete via Archive Link Path Traversal in DbGate](dbgate_archive_link_path_traversal.md) | [dbgate/dbgate](https://github.com/dbgate/dbgate) |
| Critical (9.8) | [Arbitrary File Read/Write via `file://` Protocol in DbGate jsldata Controller](dbgate_jsldata_file_read_write.md) | [dbgate/dbgate](https://github.com/dbgate/dbgate) |
| Critical (9.1) | [Arbitrary File Write via `filePath` in `config/create-connections-and-settings-zip` in DbGate](dbgate_config_zip_arbitrary_write.md) | [dbgate/dbgate](https://github.com/dbgate/dbgate) |
| Critical (9.1) | [Arbitrary File Write via `outputFile` in `database-connections/export-model-sql` in DbGate](dbgate_export_model_sql_arbitrary_write.md) | [dbgate/dbgate](https://github.com/dbgate/dbgate) |
| Critical (9.1) | [Arbitrary File Copy and Path Traversal Write via `files/save-uploaded-file` in DbGate](dbgate_save_uploaded_file_path_traversal.md) | [dbgate/dbgate](https://github.com/dbgate/dbgate) |
| High (8.8) | [LibrePhotos 1.2.1 ExifTool Argument Injection via Person Name RCE](LibrePhotos_Person_Name_ExifTool_Argument_Injection_RCE.md) | LibrePhotos/librephotos |
| High (8.8) | [MoviePilot v3 Workflow Fork API Pickle Deserialization RCE](MoviePilot_Workflow_Fork_Pickle_Deserialization_RCE.md) | jxxghp/MoviePilot |
| High (8.8) | [peewee pwiz Code Injection via Unescaped Database Metadata — Import-Time RCE](Peewee_pwiz_Database_Metadata_Code_Injection.md) | coleifer/peewee |
| High (8.8) | [Termix 2.9.1 File-Manager transferToHost Arbitrary File Write on the Termix Server](Termix_FileManager_transferToHost_Arbitrary_File_Write.md) | Termix-SSH/Termix |
| High (8.3) | [AiSOC (main) Federated Search free_text ES|QL Injection on Customer Elasticsearch](AiSOC_Federated_Search_ESQL_Injection.md) | beenuar/AiSOC |
| High (8.3) | [Knip Workspaces Configuration Path Traversal Leading to Arbitrary File Deletion and Overwrite via `knip --fix`](Knip_Workspaces_Config_Path_Traversal_File_Deletion_Overwrite.md) | webpro/knip |
| High (8.2) | [big-AGI 2.1.1 llmOllama Unauthenticated SSRF via Client-Controlled `ollamaHost`](BigAGI_llmOllama_Unauthenticated_SSRF.md) | enricoros/big-AGI |
| High (8.2) | [MiroTalk roomAction checkPassword Unauthenticated Room-Password Brute Force](MiroTalk_roomAction_checkPassword_Unauthenticated_Brute_Force.md) | miroslavpejic85/mirotalk |
| High (8.2) | [SSRF bypass in October CMS ResizeImages via IPv6-mapped IPv4 address encoding](October_CMS_SSRF_IPv6_Mapped_IPv4_Bypass.md) | octobercms/october |
| High (8.2) | [open-wearables Unauthenticated Provider OAuth Authorization — Arbitrary User Binding and Attacker-Controlled Redirect](OpenWearables_OAuth_Unauthenticated_Bind_Open_Redirect.md) | the-momentum/open-wearables |
| High (8.2) | [open-wearables Strava Webhook Timestamp-Only "Signature" — Forged Events Delete Health Data and Revoke Connections](OpenWearables_Strava_Webhook_Forged_Event_Data_Destruction.md) | the-momentum/open-wearables |
| High (8.1) | [Chitchatter SDK postMessage Identity Key Injection](Chitchatter_SDK_postMessage_Identity_Key_Injection.md) | jeremyckahn/chitchatter |
| High (8.1) | [NocoBase 2.1.40 SQLite Filter Array Operator SQL Injection](NocoBase_SQLite_FilterParser_SQL_Injection.md) | nocobase/nocobase |
| High (8.1) | [Incomplete scheme validation in October CMS ResizeImages enables PHP stream wrapper injection](October_CMS_Stream_Wrapper_Injection.md) | octobercms/october |
| High (8.1) | [WebSocket-for-Python (ws4py) wss Client TLS Certificate and Hostname Verification Disabled by Default](WebSocket_for_Python_wss_TLS_Certificate_Validation_Disabled_by_Default.md) | Lawouach/WebSocket-for-Python |
| High (7.5) | [big-AGI 2.1.1 Server-Side LLM API Key Exfiltration via Client-Controlled `oaiHost`](BigAGI_llmOpenAI_Env_API_Key_Exfiltration.md) | enricoros/big-AGI |
| High (7.5) | [Path Traversal in MediaUploadTrait::deleteFile() leading to arbitrary file deletion](Grav_CMS_Path_Traversal_Arbitrary_File_Deletion.md) | getgrav/grav |
| High (7.5) | [Path Traversal in `runners/files` via Unvalidated `runid` in DbGate](dbgate_runners_files_path_traversal.md) | [dbgate/dbgate](https://github.com/dbgate/dbgate) |
| High (7.3) | [MCPHub v1.0.45 OpenAPI passthroughHeaders Credential Exfiltration](MCPHub_OpenAPI_passthroughHeaders_Credential_Exfiltration.md) | samanhappy/mcphub |

Total: 28 advisories.