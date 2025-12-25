# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an XSOAR (Cortex XSOAR) integration that implements GitOps workflows for Palo Alto Networks firewall and Panorama configuration management. It synchronizes configurations between PAN-OS devices and GitHub, enabling version-controlled infrastructure with pull request-based change management.

## Architecture

### Core Components

**Single Python File Structure**: The entire integration lives in `XSOAR_GitOps_Integration.py` (~2400 lines). This is standard for XSOAR integrations which deploy as self-contained units.

**Two Main Client Classes**:

1. **PanOsClient** (line 107): Handles all PAN-OS XML API interactions
   - Uses `/api/` endpoint with XML API calls
   - Uses `/api/?type=export` for config exports (bypasses XML response wrappers)
   - Methods include `execute_api_call()`, `export_config()`, `get_running_config()`, `get_candidate_config()`
   - Lock management for commit and config locks

2. **GitHubClient** (line 401): Handles all GitHub API interactions
   - Uses both REST API (`/contents/`) and Git Data API (`/git/blobs`, `/git/trees`)
   - Git Data API is critical for handling files >1MB (firewall configs are often large)
   - Methods include `get_file_content()`, `get_blob_content()`, `create_branch()`, `push_file()`

### Command Entry Points

XSOAR routes commands via `demisto.command()` in the `main()` function (line 2352):

- **`test-module`**: Connectivity test (line 2336)
- **`fetch-incidents`**: Polling function that monitors GitHub commits (line 2155)
- **`firewall-git-sync`**: Main sync workflow - calls `sync_firewall_logic()` (line 972)
- **`firewall-git-finalize`**: Post-merge workflow - calls `finalize_deployment_logic()` (line 1795)
- **`firewall-git-test-connectivity`**: Debug connectivity test

### Device Type Modes

The integration supports two distinct workflows based on `device_type` parameter:

**Firewall Mode** (`device_type='Firewall'`):
- Single-file workflow
- Stores entire config in one XML file (e.g., `firewall_config.xml`)
- Simpler diff and merge process

**Panorama Mode** (`device_type='Panorama'`):
- Multi-section workflow with directory structure
- Sections: `device-groups/`, `templates/`, `template-stacks/`
- Uses `SECTION_TYPE_MAP` (line 14) to handle plural/singular conversions
- Each section stored in separate files (e.g., `device-groups/prod-dg.xml`)
- Includes snapshot mechanism for drift detection
- More complex but handles Panorama's hierarchical configuration

### Key Workflows

**Sync Workflow** (`sync_firewall_logic()`):
1. Check for active workflows (prevent concurrent changes via commit locks)
2. Drift detection (compare running config vs GitHub snapshot)
3. Check for PR trigger (via config locks with specific admin names)
4. Validate configuration
5. Extract affected sections (Panorama only - parses change summary)
6. Create feature branch(es)
7. Push changes and create pull request

**Finalize Workflow** (`finalize_deployment_logic()`):
1. Identify changed sections from merge commit
2. Fetch candidate configuration from device
3. Safety check: verify main branch matches candidate config
4. Smart unlock: remove locks by specific admin who created the PR
5. Update snapshots (Panorama only)
6. Optional: commit changes to device

### Critical Implementation Details

**Lock Detection Pattern**:
- Commit locks with comment containing "AUTOMATION" indicate active workflow
- Config locks are used to trigger PRs - admin name in lock owner identifies who initiated
- Lock commands differ by device type via `build_lock_command(lock_type, device_type)` (line 26)

**Branch Naming**:
- Uses `sanitize_path_for_branch()` (line 51) to create safe branch prefixes from config paths
- Format: `{path-prefix}-{section-type}-{section-name}` or `{path-prefix}-drift-detection`
- Handles nested paths like `Panoramas/M200s/pano.xml` → `Panoramas-M200s-`

**Large File Handling**:
- GitHub REST API has 1MB limit for `/contents/` endpoint
- Integration checks if `content` field is present in response
- Falls back to Git Blob API (`/git/blobs/{sha}`) for large files
- This is why `GitHubClient` has both `base_url` and `repo_root_url`

**Configuration Export**:
- Uses `type=export&category=configuration` API call
- Returns raw XML without `<response><result>` wrappers
- Different from `type=config&action=show` which returns wrapped XML
- Method `extract_config_from_response()` (line 75) strips wrappers when needed

**Drift Detection** (Panorama only):
- Compares running config SHA against snapshot SHA
- Automatically creates `drift-detection` branch when mismatch found
- Prevents new PRs while drift exists
- Requires merge of drift PR before proceeding

**Section Extraction** (Panorama only):
- Parses change summary from `<request><cmd>show config list changes</cmd></request>`
- Extracts paths like `/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='prod-dg']`
- Maps to section types and names for targeted updates
- Auto-detects new sections not in change list

## Development Guidelines

### XSOAR Integration Context

**Execution Environment**:
- Runs inside XSOAR Docker containers
- Uses `demisto` global object for all I/O (not available in local testing)
- `demisto.params()` for configuration parameters
- `demisto.args()` for command arguments
- `demisto.results()` or `return_results()` for output
- `demisto.incidents()` for fetch-incidents
- `demisto.debug()`, `demisto.error()` for logging

**No Local Testing**:
- Cannot run this file directly - requires XSOAR runtime
- Debug by adding `demisto.debug()` statements
- Test via XSOAR integration test module or playground

### Configuration Parameters

From `params` (integration settings):
- `panorama_host`: PAN-OS device hostname/IP
- `panorama_apikey`: API key for PAN-OS
- `github_token`: GitHub Personal Access Token
- `repo_owner`: GitHub repo owner
- `repo_name`: GitHub repo name
- `config_path`: Path to config file (default: `firewall_config.xml`)
- `device_type`: "Panorama" or "Firewall" (default: "Panorama")
- `insecure`: Skip SSL verification (default: False)

### XML Handling Patterns

**Parsing**: Uses `xml.etree.ElementTree` (imported as `ET`)
```python
root = ET.fromstring(xml_string)
element = root.find('.//path/to/element')
value = element.findtext('tag_name')
```

**XPath-like Queries**: Use `.findall('.//entry')` for nested searches

**Converting to String**: `ET.tostring(element, encoding='unicode')`

### Error Handling Philosophy

- API calls return `None` on failure (not exceptions)
- Always check if result is `None` before proceeding
- Use `try/except` at outer orchestration level
- Log errors via `demisto.error()` for XSOAR visibility
- Return `CommandResults` with error status rather than raising

### State Management

**Integration Context** (persists between runs):
- `get_integration_context()` / `set_integration_context()` (line 2202, 2206)
- Used for tracking last processed commit SHA in fetch-incidents
- Prevents duplicate incident creation

**No Database**: All state in XSOAR context or GitHub repository

## Common Modification Scenarios

### Adding New Device Types
1. Update `device_type` validation in `main()` (line 2370)
2. Add routing logic in `sync_firewall_logic()` and `finalize_deployment_logic()`
3. Add lock command patterns in `build_lock_command()`

### Modifying Section Types (Panorama)
1. Update `SECTION_TYPE_MAP` dictionary (line 14)
2. Ensure path parsing handles new section patterns
3. Test section extraction logic

### Changing GitHub Structure
1. Modify file path construction in sync/finalize workflows
2. Update drift detection snapshot paths
3. Ensure backward compatibility with existing repos

### Adding Validation Steps
1. Add validation in sync workflow after config fetch
2. Return early with error status if validation fails
3. Include validation details in PR description

## API Rate Limits & Performance

**GitHub API**: 5000 requests/hour with authentication
- Large configs use Git Data API (blob) which is more efficient
- Branch operations use Git refs API

**PAN-OS API**: No documented rate limits but respect device load
- Config exports can be slow on large Panoramas (60s timeout)
- Lock checks are lightweight

## Security Considerations

**Secrets Management**:
- API keys passed via XSOAR vault/parameters (encrypted)
- Never log API keys or tokens
- GitHub token needs repo write permissions

**SSL Verification**:
- Disabled by default for PAN-OS (self-signed certs common)
- `urllib3.disable_warnings()` suppresses warnings
- Configurable via `insecure` parameter
