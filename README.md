# Security Advisories

Independent vulnerability advisories. Each advisory contains an
affected-versions table, vulnerability details, PoC with dynamic
verification output, impact analysis, and remediation guidance.

| Severity | Advisory | Project |
|---|---|---|
| High (3.1) | [`/mux` Terminal WebSocket Accepts Any Origin and Any Terminal ID in Agent Orchestrator, Allowing Hijack of Existing Agent Session PTYs](agentorchestrator_mux_terminal_no_ownership.md) | Untrivial-ai/agent-orchestrator |
| High (3.1) | [AiSOC (main) Federated Search free_text ES|QL Injection on Customer Elasticsearch](AiSOC_Federated_Search_ESQL_Injection.md) | beenuar/AiSOC |
| Critical (3.1) | [Arbitrary File Copy and Path Traversal Write via `files/save-uploaded-file` in DbGate](dbgate_save_uploaded_file_path_traversal.md) | dbgate/dbgate |
| Critical (3.1) | [Arbitrary File Read/Write via `file://` Protocol in DbGate jsldata Controller](dbgate_jsldata_file_read_write.md) | dbgate/dbgate |
| Critical (3.1) | [Arbitrary File Read/Write/Delete via Archive Link Path Traversal in DbGate](dbgate_archive_link_path_traversal.md) | dbgate/dbgate |
| Critical (3.1) | [Arbitrary File Write via `filePath` in `config/create-connections-and-settings-zip` in DbGate](dbgate_config_zip_arbitrary_write.md) | dbgate/dbgate |
| Critical (3.1) | [Arbitrary File Write via `outputFile` in `database-connections/export-model-sql` in DbGate](dbgate_export_model_sql_arbitrary_write.md) | dbgate/dbgate |
| High (3.1) | [Chitchatter SDK postMessage Identity Key Injection](Chitchatter_SDK_postMessage_Identity_Key_Injection.md) | jeremyckahn/chitchatter |
| High (3.1) | [Code Injection via Unescaped Database Metadata in pwiz Leads to Import-Time RCE in peewee](Peewee_pwiz_Database_Metadata_Code_Injection.md) | coleifer/peewee |
| Critical (3.1) | [ConvertX v0.19.0 Hardcoded Default JWT Secret — Full Authentication Bypass](ConvertX_Hardcoded_Default_JWT_Secret_Auth_Bypass.md) | C4illin/ConvertX |
| Critical (3.1) | [Documented Default Administrator Credentials Lead to Unauthenticated Platform Takeover in open-wearables](OpenWearables_Default_Admin_Credentials_Takeover.md) | the-momentum/open-wearables |
| High (3.1) | [Forged Strava Webhook Events Enable Unauthenticated Health-Data Deletion and Connection Revocation in open-wearables](OpenWearables_Strava_Webhook_Forged_Event_Data_Destruction.md) | the-momentum/open-wearables |
| High (3.1) | [GraphQL WebSocket `connection_init` Authenticates as Admin Under SIMPLE_LOGIN in Suwayomi-Server](suwayomi_ws_connection_init_admin_bypass.md) | Suwayomi/Suwayomi-Server |
| Critical (3.1) | [Hardcoded Default JWT Signing Secret in Securo Enables Offline Superuser Token Forgery](securo_backend_default_jwt_secret.md) | securo-finance/securo |
| High (3.1) | [Incomplete scheme validation in October CMS ResizeImages enables PHP stream wrapper injection](October_CMS_Stream_Wrapper_Injection.md) | octobercms/october |
| High (3.1) | [Knip Workspaces Configuration Path Traversal Leading to Arbitrary File Deletion and Overwrite via `knip --fix`](Knip_Workspaces_Config_Path_Traversal_File_Deletion_Overwrite.md) | webpro/knip |
| High (3.1) | [LibrePhotos 1.2.1 ExifTool Argument Injection via Person Name RCE](LibrePhotos_Person_Name_ExifTool_Argument_Injection_RCE.md) | LibrePhotos/librephotos |
| High (3.1) | [MCPHub v1.0.45 OpenAPI passthroughHeaders Credential Exfiltration](MCPHub_OpenAPI_passthroughHeaders_Credential_Exfiltration.md) | samanhappy/mcphub |
| High (3.1) | [MiroTalk roomAction checkPassword Unauthenticated Room-Password Brute Force](MiroTalk_roomAction_checkPassword_Unauthenticated_Brute_Force.md) | miroslavpejic85/mirotalk |
| Critical (3.1) | [Mobile-MCP Streamable HTTP Server Missing Authentication Exposes Full Mobile-Device Control](MobileMCP_Streamable_HTTP_No_Authentication_Device_Control_Exposure.md) | mobile-next/mobile-mcp |
| High (3.1) | [MoviePilot v3 Workflow Fork API Pickle Deserialization RCE](MoviePilot_Workflow_Fork_Pickle_Deserialization_RCE.md) | jxxghp/MoviePilot |
| High (3.1) | [NocoBase 2.1.40 SQLite Filter Array Operator SQL Injection](NocoBase_SQLite_FilterParser_SQL_Injection.md) | nocobase/nocobase |
| High (3.1) | [Path Traversal in `runners/files` via Unvalidated `runid` in DbGate](dbgate_runners_files_path_traversal.md) | dbgate/dbgate |
| High (3.1) | [Path Traversal in MediaUploadTrait::deleteFile() leading to arbitrary file deletion](Grav_CMS_Path_Traversal_Arbitrary_File_Deletion.md) | getgrav/grav |
| Critical (3.1) | [Public Default MCP JWT Secret and Unauthenticated `/mcp` Exposure in Securo Enable Cross-User Financial Data Access](securo_mcp_default_jwt_secret.md) | securo-finance/securo |
| High (3.1) | [REST Extension Install/Uninstall Endpoints Skip the Multi-User Permission Checks, Enabling Arbitrary Code Execution via Crafted Extension in Suwayomi-Server](suwayomi_rest_extension_install_permission_bypass.md) | Suwayomi/Suwayomi-Server |
| High (3.1) | [Server-Side LLM API Key Exfiltration via Client-Controlled `oaiHost` with Environment-Key Fallback in big-AGI](BigAGI_llmOpenAI_Env_API_Key_Exfiltration.md) | enricoros/big-AGI |
| High (3.1) | [SSRF bypass in October CMS ResizeImages via IPv6-mapped IPv4 address encoding](October_CMS_SSRF_IPv6_Mapped_IPv4_Bypass.md) | octobercms/october |
| High (3.1) | [Static Safety-Check Bypass in AI Strategy Code Pipeline Leads to Remote Code Execution in TickFlow Stock Panel](tickstockpanel_strategy_validation_bypass_rce.md) | shy3130/tick-stock-panel |
| Critical (3.1) | [Stored Cross-Site Scripting in HortusFox Chat Messages (AJAX Render Path) Leads to Administrator Session Hijacking](hortusfox_chat_stored_xss.md) | danielbrendel/hortusfox-web |
| High (3.1) | [Termix 2.9.1 File-Manager transferToHost Arbitrary File Write on the Termix Server](Termix_FileManager_transferToHost_Arbitrary_File_Write.md) | Termix-SSH/Termix |
| Critical (3.1) | [Unauthenticated Bilibili Session-Credential Export in OpenBiliClaw Default Deployment](openbiliclaw_unauth_bilibili_cookie_export.md) | whiteguo233/OpenBiliClaw |
| Critical (3.1) | [Unauthenticated Configuration Tampering in OpenBiliClaw Enables LLM Traffic Hijacking and an Arbitrary-Process Backdoor](openbiliclaw_unauth_config_tamper_rce.md) | whiteguo233/OpenBiliClaw |
| High (3.1) | [Unauthenticated Loopback Shell-Terminal Spawn and `/mux` Command Injection in Agent Orchestrator Lead to Remote Code Execution](agentorchestrator_shell_terminal_spawn_rce.md) | Untrivial-ai/agent-orchestrator |
| High (3.1) | [Unauthenticated Mobile Enable Endpoint in Agent Orchestrator Returns the Plaintext Connection Password to Browser Content and Opens Remote Access](agentorchestrator_mobile_password_tunnel.md) | Untrivial-ai/agent-orchestrator |
| High (3.1) | [Unauthenticated Provider OAuth Authorization Enables Arbitrary User Binding and Attacker-Controlled Redirect in open-wearables](OpenWearables_OAuth_Unauthenticated_Bind_Open_Redirect.md) | the-momentum/open-wearables |
| High (3.1) | [Unauthenticated SSRF via Client-Controlled `ollamaHost` in big-AGI llmOllama tRPC Procedures](BigAGI_llmOllama_Unauthenticated_SSRF.md) | enricoros/big-AGI |
| High (3.1) | [WebSocket-for-Python (ws4py) wss Client TLS Certificate and Hostname Verification Disabled by Default](WebSocket_for_Python_wss_TLS_Certificate_Validation_Disabled_by_Default.md) | Lawouach/WebSocket-for-Python |
| Critical (3.1) | [Zilla http-filesystem Binding Unauthenticated Path Traversal](Zilla_Http_Filesystem_Binding_Path_Traversal.md) | aklivity/zilla |

Total: 39 advisories.
