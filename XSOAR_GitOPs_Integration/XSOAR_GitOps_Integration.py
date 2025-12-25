"""
Firewall GitOps Sync Integration
"""

import base64
import re
import xml.etree.ElementTree as ET
import requests
import urllib3
import time
import json # Added for JSON parsing in fetch-incidents


SECTION_TYPE_MAP = {
    'device-groups': 'device-group',
    'templates': 'template',
    'template-stacks': 'template-stack'
}


# Disable insecure warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

''' CLIENT CLASSES '''

def build_lock_command(lock_type, device_type):
    """
    Build the appropriate lock command based on device type.

    Args:
        lock_type: 'commit' or 'config'
        device_type: 'Panorama' or 'Firewall'

    Returns:
        XML command string
    """
    if device_type == 'Panorama':
        if lock_type == 'commit':
            return '<show><commit-locks></commit-locks></show>'
        elif lock_type == 'config':
            return '<show><config-locks></config-locks></show>'
    else:  # Firewall
        if lock_type == 'commit':
            return '<show><commit-locks><vsys>all</vsys></commit-locks></show>'
        elif lock_type == 'config':
            return '<show><config-locks><vsys>all</vsys></config-locks></show>'

    # Fallback (should not reach here)
    return '<show><commit-locks></commit-locks></show>'

def sanitize_path_for_branch(config_path):
    """
    Convert file path to safe branch prefix.
    Examples:
      'firewall_config.xml' -> ''
      'Firewalls/InternetFW/config.xml' -> 'Firewalls-InternetFW-'
      'Panoramas/M200s/pano.xml' -> 'Panoramas-M200s-'
    """
    # Remove filename, keep only directory path
    path_parts = config_path.split('/')

    # If only filename (root), return empty prefix
    if len(path_parts) == 1:
        return ''

    # Get directory path (everything except filename)
    dir_path = '/'.join(path_parts[:-1])

    # Sanitize: replace slashes with dashes, remove special chars
    safe_prefix = re.sub(r'[^a-zA-Z0-9]', '-', dir_path)

    # Add trailing dash for clarity
    return safe_prefix + '-'

def extract_config_from_response(api_response_root):
    """
    Extract the actual <config> element from PanOS API response.
    
    PanOS returns: <response><result><config>...</config></result></response>
    We want just: <config>...</config>
    
    Args:
        api_response_root: XML root from execute_api_call
    
    Returns:
        XML string of just the config element, or None if not found
    """
    try:
        # Navigate to the config element inside result
        config_elem = api_response_root.find('.//result/config')
        
        if config_elem is not None:
            # Convert just the config element to string
            config_str = ET.tostring(config_elem, encoding='unicode')
            demisto.debug(f"Extracted config element ({len(config_str)} chars)")
            return config_str
        else:
            demisto.error("Could not find config element in API response")
            return None
            
    except Exception as e:
        demisto.error(f"Failed to extract config from response: {str(e)}")
        return None



class PanOsClient:
    """
    Client to interact with Panorama/Firewall XML API.
    """
    def __init__(self, host, api_key, verify_ssl=False):
        self.host = host if host.startswith('http') else f"https://{host}"
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.base_url = f"{self.host}/api/"

    def execute_api_call(self, my_params):
        """Wrapper for API calls with error handling"""
        my_params['key'] = self.api_key
        try:
            res = requests.get(
                self.base_url,
                params=my_params,
                verify=self.verify_ssl,
                timeout=30
            )
            res.raise_for_status()
            return self._parse_xml_response(res.content)
        except Exception as e:
            demisto.debug(f"PanOS Error: {str(e)}")
            return None
        
    def export_config(self, config_type='running'):
        """
        Export configuration using the export API endpoint.
        Returns the raw configuration XML without response wrappers.
        
        Args:
            config_type: 'running' or 'candidate' (default: 'running')
        
        Returns:
            str: Raw XML configuration, or None on failure
        """
        try:
            # Build export URL
            url = f"https://{self.hostname}/api/"
            params = {
                'type': 'export',
                'category': 'configuration',
                'key': self.api_key
            }
            
            # If candidate config requested, add from parameter
            if config_type == 'candidate':
                params['from'] = 'candidate'
            
            demisto.debug(f"Exporting {config_type} config via export API...")
            
            # Make request with longer timeout for large configs
            response = requests.get(
                url,
                params=params,
                verify=self.verify_cert,
                timeout=60
            )
            
            if response.status_code == 200:
                # Response is the raw XML config - no parsing needed!
                config_xml = response.text
                
                demisto.debug(f"Export successful: {len(config_xml)} characters")
                
                # Verify it starts with valid XML
                if config_xml.strip().startswith('<?xml') or config_xml.strip().startswith('<config'):
                    return config_xml
                else:
                    demisto.error(f"Export returned unexpected format: {config_xml[:200]}")
                    return None
            else:
                demisto.error(f"Export failed with status {response.status_code}: {response.text[:500]}")
                return None
                
        except Exception as e:
            demisto.error(f"Export config exception: {str(e)}")
            return None
    def export_running_config(self):
        """
        Export running configuration - tries export API first, falls back to op command.
        Returns the raw configuration XML.
        
        Returns:
            str: Raw XML configuration, or None on failure
        """
        try:
            # METHOD 1: Try export API first
            demisto.debug("Attempting to export running config via export API...")
            
            url = f"https://{self.hostname}/api/"
            params = {
                'type': 'export',
                'category': 'configuration',
                'key': self.api_key
            }
            
            response = requests.get(
                url,
                params=params,
                verify=self.verify_cert,
                timeout=60
            )
            
            demisto.debug(f"Export API response status: {response.status_code}")
            demisto.debug(f"Export API response length: {len(response.text)} chars")
            
            if response.status_code == 200:
                config_xml = response.text
                
                # Verify it's valid XML
                if config_xml.strip().startswith('<?xml') or config_xml.strip().startswith('<config'):
                    # Check if we got a substantial config (should be ~20MB for Panorama)
                    if len(config_xml) > 1000000:  # More than 1MB
                        demisto.debug(f"Export API success: {len(config_xml)} characters")
                        return config_xml
                    else:
                        demisto.debug(f"Export API returned small config ({len(config_xml)} chars), trying fallback...")
                else:
                    demisto.debug(f"Export API returned unexpected format: {config_xml[:200]}")
            else:
                demisto.debug(f"Export API failed with status {response.status_code}: {response.text[:500]}")
            
        except Exception as e:
            demisto.debug(f"Export API exception: {str(e)}")
        
        # METHOD 2: Fallback to op command (same as get_candidate_config but for running)
        try:
            demisto.debug("Falling back to op command for running config...")
            
            root = self.execute_api_call({
                'type': 'op',
                'cmd': '<show><config><running></running></config></show>'
            })
            
            if not root:
                demisto.error("Op command returned None for running config")
                return None
            
            # Extract <config> element from response wrapper
            config_elem = root.find('.//result/config')
            
            if config_elem is not None:
                config_str = ET.tostring(config_elem, encoding='unicode')
                demisto.debug(f"Fallback op command success: {len(config_str)} characters")
                
                # Verify we got a substantial config
                if len(config_str) > 1000000:
                    return config_str
                else:
                    demisto.debug(f"Op command returned small config: {len(config_str)} chars")
                    return config_str  # Return it anyway
            else:
                demisto.error("Could not find config element in running config response")
                
                # Debug: log response structure
                full_resp = ET.tostring(root, encoding='unicode')
                demisto.debug(f"Response structure (first 1000 chars): {full_resp[:1000]}")
                
                return None
                
        except Exception as e:
            demisto.error(f"Fallback op command exception: {str(e)}")
            return None



    def get_candidate_config(self):
        """
        Get candidate configuration using op command.
        Extracts and returns the config XML from the API response wrapper.
        
        Returns:
            str: Config XML string, or None on failure
        """
        try:
            demisto.debug("Fetching candidate config via op command...")
            
            root = self.execute_api_call({
                'type': 'op',
                'cmd': '<show><config><candidate></candidate></config></show>'
            })
            
            if not root:
                demisto.error("Op command returned None for candidate config")
                return None
            
            # Extract <config> element from response wrapper
            # Response structure: <response><result><config>...</config></result></response>
            config_elem = root.find('.//result/config')
            
            if config_elem is not None:
                config_str = ET.tostring(config_elem, encoding='unicode')
                demisto.debug(f"Candidate config retrieved: {len(config_str)} characters")
                return config_str
            else:
                demisto.error("Could not find config element in candidate response")
                
                # Debug: log response structure
                full_resp = ET.tostring(root, encoding='unicode')
                demisto.debug(f"Response structure (first 1000 chars): {full_resp[:1000]}")
                
                return None
                
        except Exception as e:
            demisto.error(f"Get candidate config exception: {str(e)}")
            return None
    def _parse_xml_response(self, xml_content):
        try:
            root = ET.fromstring(xml_content)
            if root.get('status') == 'error':
                demisto.debug(f"PanOS API Logic Error: {xml_content}")
                return None
            return root
        except ET.ParseError:
            demisto.debug("PanOS XML Parse Error")
            return None

    def validate_candidate_config(self):
        """
        Runs full validation and POLLS the Job ID until completion.
        Returns: (bool_success, details_string)
        """
        # 1. KICK OFF THE JOB
        cmd = {'type': 'op', 'cmd': '<validate><full></full></validate>'}
        root = self.execute_api_call(cmd)

        job_id = None
        if root is not None:
            job_node = root.find('.//job')
            if job_node is not None:
                job_id = job_node.text

        if not job_id:
            return False, "Failed to start validation job (No Job ID returned)."

        demisto.debug(f"Validation Job ID {job_id} started. Polling for results...")

        # 2. POLL THE JOB (Max 60 retries * 5s = 5 minutes)
        max_retries = 60
        for _ in range(max_retries):
            time.sleep(5)

            check_cmd = {'type': 'op', 'cmd': f'<show><jobs><id>{job_id}</id></jobs></show>'}
            check_root = self.execute_api_call(check_cmd)

            if check_root is not None:
                # FIX: Find the <job> node first to avoid grabbing the wrong parent <result>
                job_node = check_root.find('.//job')

                if job_node is not None:
                    job_status = job_node.findtext('status') # ACT or FIN
                    # FIX: Grab result specifically from inside the job node
                    job_result = job_node.findtext('result') # OK or FAIL

                    if job_status == 'FIN':
                        # Job finished! Now we parse the output details.
                        details_node = job_node.find('details')

                        # Collect all <line> entries inside details
                        output_lines = []
                        if details_node is not None:
                            for line in details_node.findall('line'):
                                if line.text:
                                    output_lines.append(line.text)

                        full_output = "\n".join(output_lines)

                        # Robust Check:
                        # 1. Check if result is 'OK'
                        # 2. OR if the text explicitly says "Configuration is valid" (handles cases where result is missing)
                        is_result_ok = (job_result == 'OK')
                        is_text_valid = "configuration is valid" in full_output.lower()
                        is_text_invalid = "configuration is invalid" in full_output.lower()

                        if (is_result_ok or is_text_valid) and not is_text_invalid:
                            return True, full_output
                        else:
                            return False, f"Validation Failed.\nResult: {job_result}\nDetails:\n{full_output}"

        return False, "Validation Job timed out (did not finish in 300s)."

    def add_system_lock(self):
        # (Same as before)
        comment = "AUTOMATION: Waiting for PR Approval. Do not remove."
        cmd = {'type': 'op', 'cmd': f'<request><commit-lock><add><comment>{comment}</comment></add></commit-lock></request>'}
        root = self.execute_api_call(cmd)
        if root is not None:
            xml_str = ET.tostring(root, encoding='unicode')
            if 'success' in xml_str.lower() or 'added' in xml_str.lower():
                return True
        return False

class GitHubClient:
    """
    Client to interact with GitHub API.
    Updated to use Git Data API (Blobs/Trees) to bypass 1MB file limit.
    """

    def __init__(self, token, repo_owner, repo_name):
        self.token = token
        self.repo_owner = repo_owner
        self.repo_name = repo_name
        # RESTORED: Points to /contents/ to maintain compatibility with external logic
        self.base_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/contents/"
        # NEW: Points to repo root for Git Data API (Blobs, Trees, Commits)
        self.repo_root_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}"
        self.headers = {
            'Authorization': f"Bearer {self.token}",
            'Accept': 'application/vnd.github.v3+json'
        }

    def get_file_content(self, file_path, branch="main"):
        """
        Get file content. Handles files > 1MB by checking if 'content' is present
        or if we need to fetch the blob.
        """
        # Use base_url which already includes /contents/
        url = self.base_url + file_path
        try:
            res = requests.get(url, headers=self.headers, params={"ref": branch})
            if res.status_code == 200:
                data = res.json()
                
                # Case 1: Small file, content is in response
                if 'content' in data and data['content']:
                    return base64.b64decode(data['content']).decode('utf-8')
                
                # Case 2: Large file, content is missing, use SHA to get Blob
                if 'sha' in data:
                    return self.get_blob_content(data['sha'])
                    
            return None
        except Exception as e:
            demisto.debug(f"Error fetching file content: {str(e)}")
            return None

    def get_blob_content(self, file_sha):
        """Fetch raw blob content for large files"""
        # Use repo_root_url for git/blobs
        url = f"{self.repo_root_url}/git/blobs/{file_sha}"
        res = requests.get(url, headers=self.headers)
        if res.status_code == 200:
            data = res.json()
            content = base64.b64decode(data['content']).decode('utf-8')
            return content
        return None

    def get_branch_sha(self, branch_name):
        # Use repo_root_url for git/ref
        url = f"{self.repo_root_url}/git/ref/heads/{branch_name}"
        res = requests.get(url, headers=self.headers)
        if res.status_code == 200:
            return res.json()['object']['sha']
        return None

    def get_latest_commit_details(self, branch="main"):
        """Fetches the latest commit SHA and timestamp for a branch (Used for Polling)."""
        url = f"{self.repo_root_url}/commits/{branch}"
        res = requests.get(url, headers=self.headers)
        if res.status_code == 200:
            data = res.json()
            return {
                'sha': data['sha'],
                'date': data['commit']['committer']['date'], # ISO 8601 string
                'message': data['commit']['message'],
                'author': data['commit']['author']['name']
            }
        return None

    def create_branch(self, new_branch_name, source_sha):
        url = f"{self.repo_root_url}/git/refs"
        data = {"ref": f"refs/heads/{new_branch_name}", "sha": source_sha}
        res = requests.post(url, headers=self.headers, json=data)

        if res.status_code == 201:
            return True
        elif res.status_code == 422:
            resp_json = res.json()
            message = resp_json.get('message', '')
            if 'Reference already exists' in message:
                # Branch exists - UPDATE it instead
                demisto.debug(f"Branch '{new_branch_name}' exists. Updating to SHA: {source_sha}")
                update_url = f"{self.repo_root_url}/git/refs/heads/{new_branch_name}"
                update_data = {"sha": source_sha, "force": True}  # force=True allows non-fast-forward updates
                update_res = requests.patch(update_url, headers=self.headers, json=update_data)

                if update_res.status_code == 200:
                    demisto.debug(f"Successfully updated branch '{new_branch_name}' to latest main")
                    return True
                else:
                    demisto.error(f"Failed to update branch: {update_res.status_code} - {update_res.text}")
                    return False
            else:
                demisto.debug(f"GitHub Branch Error: 422 - {message}")
                return False

        demisto.debug(f"GitHub Branch Creation Failed: {res.status_code} - {res.text}")
        return False

    def push_file(self, file_path, content, message, branch):
        """
        Push file using Git Data API (Tree/Commit) to support large files.
        Uses base64 encoding to handle files of any size (including 20MB+ Panorama configs).
        """
        try:
            # 1. Get the latest commit SHA of the branch
            branch_sha = self.get_branch_sha(branch)
            if not branch_sha:
                demisto.error(f"Could not find branch {branch}")
                return False

            # 2. Get the tree SHA of the latest commit
            commit_url = f"{self.repo_root_url}/git/commits/{branch_sha}"
            res = requests.get(commit_url, headers=self.headers)
            res.raise_for_status()
            tree_sha = res.json()['tree']['sha']

            # 3. Create a Blob for the new content
            # IMPORTANT: Use base64 encoding for large files (Panorama configs can be 20MB+)
            blob_url = f"{self.repo_root_url}/git/blobs"
            content_bytes = content.encode('utf-8')
            content_b64 = base64.b64encode(content_bytes).decode('ascii')

            blob_data = {
                "content": content_b64,
                "encoding": "base64"
            }
            res = requests.post(blob_url, headers=self.headers, json=blob_data)
            res.raise_for_status()
            new_blob_sha = res.json()['sha']

            # 4. Create a new Tree
            tree_url = f"{self.repo_root_url}/git/trees"
            tree_data = {
                "base_tree": tree_sha,
                "tree": [
                    {
                        "path": file_path,
                        "mode": "100644",
                        "type": "blob",
                        "sha": new_blob_sha
                    }
                ]
            }
            res = requests.post(tree_url, headers=self.headers, json=tree_data)
            res.raise_for_status()
            new_tree_sha = res.json()['sha']

            # 5. Create a new Commit
            new_commit_url = f"{self.repo_root_url}/git/commits"
            commit_data = {
                "message": message,
                "tree": new_tree_sha,
                "parents": [branch_sha]
            }
            res = requests.post(new_commit_url, headers=self.headers, json=commit_data)
            res.raise_for_status()
            new_commit_sha = res.json()['sha']

            # 6. Update the Branch Reference
            ref_url = f"{self.repo_root_url}/git/refs/heads/{branch}"
            ref_data = {
                "sha": new_commit_sha,
                "force": False # Standard push
            }
            res = requests.patch(ref_url, headers=self.headers, json=ref_data)
            
            if res.status_code != 200:
                demisto.error(f"❌ Failed to update branch ref: {res.status_code} {res.text}")
                return False

            demisto.debug(f"✅ Successfully pushed large file via Git Data API: {file_path}")
            return True

        except Exception as e:
            demisto.error(f"❌ Git Data API Push failed for {file_path}: {str(e)}")
            return False

    def push_multiple_files(self, files, message, branch):
        """
        Push multiple files in a SINGLE commit using Git Data API.
        Much more efficient for initial sync (creates 1 commit instead of 50+).

        Args:
            files: List of dicts with 'path' and 'content' keys
                   Example: [{'path': 'device-groups/prod.xml', 'content': '<xml>...</xml>'}, ...]
            message: Commit message
            branch: Target branch name

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if not files:
                demisto.debug("No files to push")
                return True

            demisto.debug(f"Pushing {len(files)} files in a single commit...")

            # 1. Get the latest commit SHA of the branch
            branch_sha = self.get_branch_sha(branch)
            if not branch_sha:
                demisto.error(f"Could not find branch {branch}")
                return False

            # 2. Get the tree SHA of the latest commit
            commit_url = f"{self.repo_root_url}/git/commits/{branch_sha}"
            res = requests.get(commit_url, headers=self.headers)
            res.raise_for_status()
            tree_sha = res.json()['tree']['sha']

            # 3. Create Blobs for ALL files
            tree_items = []
            for idx, file_info in enumerate(files):
                file_path = file_info['path']
                content = file_info['content']

                demisto.debug(f"Creating blob {idx+1}/{len(files)}: {file_path} ({len(content)} chars)")

                # Use base64 encoding for large file support
                blob_url = f"{self.repo_root_url}/git/blobs"
                content_bytes = content.encode('utf-8')
                content_b64 = base64.b64encode(content_bytes).decode('ascii')

                blob_data = {
                    "content": content_b64,
                    "encoding": "base64"
                }
                res = requests.post(blob_url, headers=self.headers, json=blob_data)
                res.raise_for_status()
                blob_sha = res.json()['sha']

                # Add to tree items
                tree_items.append({
                    "path": file_path,
                    "mode": "100644",
                    "type": "blob",
                    "sha": blob_sha
                })

            # 4. Create a new Tree with ALL blobs
            demisto.debug(f"Creating tree with {len(tree_items)} items...")
            tree_url = f"{self.repo_root_url}/git/trees"
            tree_data = {
                "base_tree": tree_sha,
                "tree": tree_items
            }
            res = requests.post(tree_url, headers=self.headers, json=tree_data)
            res.raise_for_status()
            new_tree_sha = res.json()['sha']

            # 5. Create a single Commit
            demisto.debug("Creating commit...")
            new_commit_url = f"{self.repo_root_url}/git/commits"
            commit_data = {
                "message": message,
                "tree": new_tree_sha,
                "parents": [branch_sha]
            }
            res = requests.post(new_commit_url, headers=self.headers, json=commit_data)
            res.raise_for_status()
            new_commit_sha = res.json()['sha']

            # 6. Update the Branch Reference
            demisto.debug("Updating branch reference...")
            ref_url = f"{self.repo_root_url}/git/refs/heads/{branch}"
            ref_data = {
                "sha": new_commit_sha,
                "force": False
            }
            res = requests.patch(ref_url, headers=self.headers, json=ref_data)

            if res.status_code != 200:
                demisto.error(f"❌ Failed to update branch ref: {res.status_code} {res.text}")
                return False

            demisto.debug(f"✅ Successfully pushed {len(files)} files in single commit")
            return True

        except Exception as e:
            demisto.error(f"❌ Batch push failed: {str(e)}")
            return False


def get_panorama_sections(pan_client: PanOsClient):
    """
    Retrieve all device-groups, templates, and template-stacks from Panorama.
    
    Returns:
        dict: {
            'device-groups': ['DG1', 'DG2', ...],
            'templates': ['T1', 'T2', ...],
            'template-stacks': ['TS1', 'TS2', ...]
        }
        Returns None if any command fails.
    """
    sections = {
        'device-groups': [],
        'templates': [],
        'template-stacks': []
    }
    
    try:
        # 1. Get Device Groups
        dg_root = pan_client.execute_api_call({
            'type': 'op',
            'cmd': '<show><devicegroups></devicegroups></show>'
        })
        if dg_root is not None:
            for entry in dg_root.findall('.//devicegroups/entry'):
                name = entry.get('name')
                if name:
                    sections['device-groups'].append(name)
        
        # 2. Get Templates (this returns BOTH templates AND template-stacks mixed together)
        tmpl_root = pan_client.execute_api_call({
            'type': 'op',
            'cmd': '<show><templates></templates></show>'
        })
        if tmpl_root is not None:
            for entry in tmpl_root.findall('.//templates/entry'):
                name = entry.get('name')
                if not name:
                    continue
                
                # Check if this entry is actually a template-stack
                is_stack_elem = entry.find('template-stack')
                is_stack = False
                
                if is_stack_elem is not None:
                    stack_value = is_stack_elem.text
                    if stack_value and stack_value.lower() == 'yes':
                        is_stack = True
                
                # Add to appropriate list
                if is_stack:
                    sections['template-stacks'].append(name)
                    demisto.debug(f"Identified '{name}' as template-stack (from templates response)")
                else:
                    sections['templates'].append(name)
                    demisto.debug(f"Identified '{name}' as regular template")
        
        # 3. OPTIONAL: Get Template Stacks separately for verification
        # This ensures we don't miss any template-stacks
        ts_root = pan_client.execute_api_call({
            'type': 'op',
            'cmd': '<show><template-stack></template-stack></show>'
        })
        if ts_root is not None:
            # Get list of stacks we already found
            existing_stacks = set(sections['template-stacks'])
            
            for entry in ts_root.findall('.//template-stack/entry'):
                name = entry.get('name')
                if name and name not in existing_stacks:
                    # Found a stack that wasn't in the templates response
                    sections['template-stacks'].append(name)
                    demisto.debug(f"Added missing template-stack '{name}' from template-stack response")
        
        demisto.debug(f"Retrieved Panorama sections: {len(sections['device-groups'])} DGs, "
                     f"{len(sections['templates'])} templates (filtered), {len(sections['template-stacks'])} stacks")
        
        return sections
        
    except Exception as e:
        demisto.error(f"Failed to retrieve Panorama sections: {str(e)}")
        return None

def parse_change_list(change_list_root):
    """
    Parse the change list XML to identify which sections were modified.
    
    Args:
        change_list_root: XML root from <show><config><list><changes>
    
    Returns:
        set: Set of tuples (section_type, section_name)
             e.g., {('device-group', 'PA-VPN'), ('template', 'PHS'), ('shared', None)}
        Returns empty set if no changes or parsing fails.
    """
    changed_sections = set()
    
    try:
        # Iterate through all change entries
        for entry in change_list_root.findall('.//journal/entry'):
            xpath = entry.findtext('xpath')
            component_type = entry.findtext('component-type')
            
            if not xpath:
                continue
            
            demisto.debug(f"Processing change: XPath={xpath}, Component={component_type}")
            
            # Parse XPath to extract section type and name
            # Example: /config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='PA-VPN']/...
            
            # Check for device-group
            dg_match = re.search(r"/device-group/entry\[@name='([^']+)'\]", xpath)
            if dg_match:
                dg_name = dg_match.group(1)
                changed_sections.add(('device-group', dg_name))
                demisto.debug(f"Found device-group change: {dg_name}")
                continue
            
            # Check for template
            tmpl_match = re.search(r"/template/entry\[@name='([^']+)'\]", xpath)
            if tmpl_match:
                tmpl_name = tmpl_match.group(1)
                changed_sections.add(('template', tmpl_name))
                demisto.debug(f"Found template change: {tmpl_name}")
                continue
            
            # Check for template-stack
            ts_match = re.search(r"/template-stack/entry\[@name='([^']+)'\]", xpath)
            if ts_match:
                ts_name = ts_match.group(1)
                changed_sections.add(('template-stack', ts_name))
                demisto.debug(f"Found template-stack change: {ts_name}")
                continue
            
            # If no specific section match, it's a shared/global change
            # Check if it's under /config/devices/entry[@name='localhost.localdomain']/ but NOT in DG/template/stack
            if '/config/devices/entry' in xpath and not any(x in xpath for x in ['/device-group/', '/template/', '/template-stack/']):
                changed_sections.add(('shared', None))
                demisto.debug("Found shared object change")
        
        demisto.info(f"Parsed {len(changed_sections)} changed sections from change list")
        return changed_sections
        
    except Exception as e:
        demisto.error(f"Failed to parse change list: {str(e)}")
        return set()


def extract_section_from_config(full_config_str, section_type, section_name):
    """
    Extract a specific section from full Panorama config.
    
    Args:
        full_config_str: Full XML config string
        section_type: 'device-group', 'template', 'template-stack', or 'shared'
        section_name: Name of the section (None for shared)
    
    Returns:
        XML string of extracted section, or None if not found
    """
    try:
        # Parse the full config
        root = ET.fromstring(full_config_str)
        
        # Navigate to localhost.localdomain entry
        localhost = root.find(".//devices/entry[@name='localhost.localdomain']")
        if not localhost:
            demisto.error("Could not find localhost.localdomain in config")
            return None
        
        if section_type == 'shared':
            # Extract everything EXCEPT device-group, template, template-stack
            shared_elem = localhost.find('shared')
            if shared_elem is not None:
                # Create wrapper
                config_root = ET.Element('config')
                config_root.set('version', root.get('version', ''))
                config_root.set('urldb', root.get('urldb', ''))
                
                devices = ET.SubElement(config_root, 'devices')
                entry = ET.SubElement(devices, 'entry')
                entry.set('name', 'localhost.localdomain')
                
                # Copy shared element
                entry.append(shared_elem)
                
                return ET.tostring(config_root, encoding='unicode')
            else:
                demisto.error("Could not find shared element")
                return None
        
        else:
            # Find the parent element based on section type
            if section_type == 'device-group':
                parent_xpath = 'device-group'
            elif section_type == 'template':
                parent_xpath = 'template'
            elif section_type == 'template-stack':
                parent_xpath = 'template-stack'
            else:
                demisto.error(f"Unknown section type: {section_type}")
                return None
            
            # Find the parent container
            parent_container = localhost.find(parent_xpath)
            
            if parent_container is None:
                demisto.error(f"Could not find {parent_xpath} container in config")
                return None
            
            # Find the specific entry by name
            section_entry = parent_container.find(f"entry[@name='{section_name}']")
            
            if section_entry is None:
                # DEBUG: List all available entries
                available_entries = [e.get('name') for e in parent_container.findall('entry')]
                demisto.error(f"Could not find {section_type} '{section_name}' in config")
                demisto.error(f"Available {section_type} entries: {available_entries[:10]}")  # Show first 10
                return None
            
            # Create wrapper structure
            config_root = ET.Element('config')
            config_root.set('version', root.get('version', ''))
            config_root.set('urldb', root.get('urldb', ''))
            
            devices = ET.SubElement(config_root, 'devices')
            entry = ET.SubElement(devices, 'entry')
            entry.set('name', 'localhost.localdomain')
            
            # Create parent container and add the section
            section_container = ET.SubElement(entry, parent_xpath)
            section_container.append(section_entry)
            
            return ET.tostring(config_root, encoding='unicode')
            
    except Exception as e:
        demisto.error(f"Extract section failed for {section_type} '{section_name}': {str(e)}")
        import traceback
        demisto.error(f"Traceback: {traceback.format_exc()}")
        return None


def check_github_structure_exists(gh_client: GitHubClient, base_path):
    """
    Check if the Panorama folder structure already exists in GitHub.
    
    Args:
        gh_client: GitHubClient instance
        base_path: Base path in repo (e.g., 'Panoramas/M200')
    
    Returns:
        bool: True if structure exists, False otherwise
    """
    try:
        # Check if device-groups folder exists
        # If it exists, we assume the structure is initialized
        dg_folder_path = f"{base_path}/device-groups" if base_path else "device-groups"
        
        # Try to get the folder - if it exists, we get content, if not, we get 404
        url = gh_client.base_url + dg_folder_path
        res = requests.get(url, headers=gh_client.headers, params={"ref": "main"})
        
        if res.status_code == 200:
            demisto.debug(f"GitHub structure exists at {base_path}")
            return True
        else:
            demisto.debug(f"GitHub structure does NOT exist at {base_path} (status: {res.status_code})")
            return False
            
    except Exception as e:
        demisto.debug(f"Error checking GitHub structure: {str(e)}")
        return False




def detect_new_sections(current_sections, gh_client: GitHubClient, base_path):
    """
    Compare current Panorama sections with what exists in GitHub to find new sections.
    
    Args:
        current_sections: Dict from get_panorama_sections()
        gh_client: GitHubClient instance
        base_path: Base path in repo
    
    Returns:
        list: List of tuples (section_type, section_name) for new sections
              e.g., [('device-group', 'NEW-DG'), ('template', 'NEW-TMPL')]
    """
    new_sections = []
    
    try:
        # For each section type, check what's in GitHub
        for section_type, section_names in current_sections.items():
            # section_type is plural: 'device-groups', 'templates', 'template-stacks'
            folder_path = f"{base_path}/{section_type}" if base_path else section_type
            
            # Get list of files in GitHub folder
            url = gh_client.base_url + folder_path
            res = requests.get(url, headers=gh_client.headers, params={"ref": "main"})
            
            github_sections = set()
            if res.status_code == 200:
                items = res.json()
                # Extract section names from filenames (remove .xml extension)
                for item in items:
                    if item['type'] == 'file' and item['name'].endswith('.xml'):
                        github_sections.add(item['name'][:-4])  # Remove .xml
            
            # Convert to singular form for consistency with parse_change_list output
            singular_type = SECTION_TYPE_MAP.get(section_type, section_type)
            
            # Find sections that exist in Panorama but not in GitHub
            for section_name in section_names:
                if section_name not in github_sections:
                    new_sections.append((singular_type, section_name))
                    demisto.debug(f"Detected new section: {singular_type}/{section_name}")
        
        if new_sections:
            demisto.info(f"Detected {len(new_sections)} new sections not in GitHub")
        
        return new_sections
        
    except Exception as e:
        demisto.error(f"Failed to detect new sections: {str(e)}")
        return []

def manage_snapshot(gh_client: GitHubClient, base_path: str, action: str, config_str: str = None, branch: str = "main"):
    """
    Manage the running config snapshot for drift detection.
    
    Args:
        gh_client: GitHub client instance
        base_path: Base path in GitHub repo
        action: 'get', 'create', or 'update'
        config_str: Config string (required for create/update)
        branch: Branch name (default: "main")
    
    Returns:
        For 'get': Config string or None
        For 'create'/'update': True/False success
    """
    snapshot_path = f"{base_path}/_snapshots/running-config.xml" if base_path else "_snapshots/running-config.xml"
    
    try:
        if action == 'get':
            demisto.debug(f"Getting snapshot from: {snapshot_path} on branch: {branch}")
            content = gh_client.get_file_content(snapshot_path, branch)
            
            if content:
                demisto.debug(f"Snapshot found: {len(content)} characters")
                return content
            else:
                demisto.debug(f"Snapshot not found at: {snapshot_path}")
                return None
        
        elif action in ['create', 'update']:
            if not config_str:
                demisto.error("Config string required for create/update")
                return False
            
            demisto.debug(f"{'Creating' if action == 'create' else 'Updating'} snapshot at: {snapshot_path} on branch: {branch}")
            demisto.debug(f"Snapshot size: {len(config_str)} characters")
            
            message = f"{'Create' if action == 'create' else 'Update'} running config snapshot"
            success = gh_client.push_file(snapshot_path, config_str, message, branch)
            
            if success:
                demisto.debug(f"Snapshot {action} successful")
            else:
                demisto.error(f"Snapshot {action} failed")
            
            return success
        
        else:
            demisto.error(f"Invalid action: {action}")
            return False
            
    except Exception as e:
        demisto.error(f"Snapshot management exception: {str(e)}")
        return None if action == 'get' else False


''' CORE LOGIC '''



def sync_firewall_logic(pan_client: PanOsClient, gh_client: GitHubClient, config_path: str, device_type: str) -> CommandResults:
    """
    Main orchestration logic for GitOps.
    - For Firewalls: Single-file workflow
    - For Panorama: Sectioned workflow with automatic structure management and drift detection
    """
    messages = []
    
    # Generate unique branch prefix from path
    path_prefix = sanitize_path_for_branch(config_path)
    
    # Output tracking variables
    status = "no_action"
    admin_name = None
    branch_name = None
    validation_result = None
    drift_detected = False
    errors = []

    # ==========================================
    # DEVICE TYPE ROUTING
    # ==========================================
    if device_type == 'Firewall':
        # ========== FIREWALL: SINGLE-FILE WORKFLOW ==========
        messages.append("### Device Type: Firewall (Single-file mode)")

        # Determine base path for snapshots (similar to Panorama)
        if config_path:
            if '/' in config_path:
                path_parts = config_path.split('/')
                if path_parts[-1].endswith('.xml'):
                    base_path = '/'.join(path_parts[:-1])
                else:
                    base_path = config_path
            else:
                if config_path.endswith('.xml'):
                    base_path = ""
                else:
                    base_path = config_path
        else:
            base_path = ""

        messages.append(f"📁 **Base Path:** `{base_path or '(root)'}`")

        # STEP 0: CHECK IF THIS IS INITIAL SYNC
        messages.append("### Step 0: Checking GitHub Structure")

        # Check if config file exists in GitHub
        existing_config = gh_client.get_file_content(config_path, "main")

        if not existing_config:
            # ========== INITIAL SYNC MODE ==========
            messages.append("🆕 **Initial Sync Mode:** Config file does not exist in GitHub. Creating...")
            status = "initial_sync"

            # Get running config from firewall
            messages.append("⬇️ Fetching running config from firewall (current deployed state)...")
            running_config_str = pan_client.export_running_config()

            if not running_config_str:
                errors.append("Could not export running config")
                return CommandResults(
                    readable_output="❌ Error: Could not export running config.",
                    outputs_prefix="FirewallSync",
                    outputs={
                        "Status": "error",
                        "AdminName": admin_name,
                        "BranchName": branch_name,
                        "ValidationResult": validation_result,
                        "DriftDetected": drift_detected,
                        "Messages": messages,
                        "Errors": errors
                    }
                )

            messages.append(f"✅ Retrieved running config ({len(running_config_str)} characters)")

            # Push running config to main branch
            messages.append("📤 Uploading running config to GitHub main branch...")
            if gh_client.push_file(config_path, running_config_str, "Initial sync: running config", "main"):
                messages.append(f"✅ Config file uploaded to `{config_path}`")

                # Create snapshot for drift detection
                messages.append("📸 Creating running config snapshot...")
                if manage_snapshot(gh_client, base_path, 'create', running_config_str, "main"):
                    messages.append("✅ Snapshot created for drift detection")
                else:
                    messages.append("⚠️ Warning: Failed to create snapshot (drift detection unavailable)")
                    errors.append("Failed to create snapshot")

                messages.append("✅ **Initial Sync Complete:** GitHub repository initialized with current running config")
                messages.append("ℹ️ **Next Steps:** Run integration again when you have changes to create a PR.")

            else:
                status = "error"
                errors.append("Failed to push config to GitHub")
                messages.append("❌ Failed to push config file to GitHub.")

            return CommandResults(
                readable_output="\n".join(messages),
                outputs_prefix="FirewallSync",
                outputs={
                    "Status": status,
                    "AdminName": admin_name,
                    "BranchName": branch_name,
                    "ValidationResult": validation_result,
                    "DriftDetected": drift_detected,
                    "Messages": messages,
                    "Errors": errors
                }
            )

        # ========== INCREMENTAL UPDATE MODE ==========
        messages.append("✅ **Incremental Update Mode:** Config file exists in GitHub.")

        # STEP 1: CHECK IF WE'RE IN AN ACTIVE WORKFLOW
        messages.append("### Step 1: Workflow State Check")
        
        commit_lock_cmd = build_lock_command('commit', device_type)
        commit_locks = pan_client.execute_api_call({
            'type': 'op', 
            'cmd': commit_lock_cmd
        })
        
        in_active_workflow = False
        if commit_locks:
            for entry in commit_locks.findall('.//entry'):
                comment = entry.findtext('comment') or ""
                if "AUTOMATION" in comment:
                    in_active_workflow = True
                    status = "pending_approval"
                    messages.append("🔄 **Active Workflow Detected:** A PR is already pending approval.")
                    break
        
        # STEP 2.5: DRIFT DETECTION
        messages.append("### Step 2.5: Drift Detection")

        # Get current running config from Panorama
        current_running = pan_client.export_running_config()

        if current_running:
            # Get snapshot from GitHub
            snapshot_running = manage_snapshot(gh_client, base_path, 'get')
            
            if snapshot_running:
                # Compare current vs snapshot
                if current_running.strip() != snapshot_running.strip():
                    drift_detected = True
                    messages.append("⚠️ **DRIFT DETECTED!** Running config differs from last committed state.")
                    messages.append("🔍 **Cause:** Someone committed changes directly to Panorama outside GitOps workflow.")
                    messages.append("📊 **Action:** Capturing current running config for review...")
                    
                    # Create drift branch and push FULL running config for manual review
                    # We don't try to identify specific sections because:
                    # 1. Change list shows candidate vs running (not helpful for drift)
                    # 2. Running config is the committed state we need to reconcile
                    
                    drift_branch = f'{path_prefix}drift-detected'
                    main_sha = gh_client.get_branch_sha("main")
                    
                    if main_sha and gh_client.create_branch(drift_branch, main_sha):
                        # Push full running config to _drift folder for manual review
                        full_drift_path = f"{base_path}/_drift/full-running-config.xml" if base_path else "_drift/full-running-config.xml"
                        
                        if gh_client.push_file(full_drift_path, current_running, "Drift detected: committed changes outside GitOps", drift_branch):
                            messages.append(f"✅ Full running config saved to `{drift_branch}` for manual review")
                            messages.append(f"📁 Path: `{full_drift_path}`")
                            
                            # Also update snapshot in drift branch to current running
                            if manage_snapshot(gh_client, base_path, 'update', current_running, drift_branch):
                                messages.append("✅ Snapshot updated in drift branch")
                            
                            status = "drift_detected"
                            branch_name = drift_branch
                            messages.append("ℹ️ **Action Required:** Review drift branch, identify changes, and merge to reconcile state")
                        else:
                            messages.append("⚠️ Failed to save drift config to GitHub")
                            errors.append("Failed to push drift config")
                    else:
                        messages.append("⚠️ Failed to create drift branch")
                        errors.append("Failed to create drift branch")
                    
                    messages.append("➡️ **Proceeding:** Continuing workflow to process candidate changes...")
                else:
                    messages.append("✅ No drift detected. Running config matches snapshot.")
            else:
                messages.append("⚠️ No snapshot found. Drift detection unavailable.")
                messages.append("💡 Snapshot will be created after next successful deployment.")
        else:
            messages.append("⚠️ Could not export running config. Skipping drift detection.")

        # STEP 3: LOCK CHECK (USER LINKING)
        messages.append("### Step 3: Checking for PR Triggers")
        
        if in_active_workflow:
            messages.append("ℹ️ Waiting for team to merge the Feature PR. No action taken.")
            return CommandResults(
                readable_output="\n".join(messages),
                outputs_prefix="FirewallSync",
                outputs={
                    "Status": status,
                    "AdminName": admin_name,
                    "BranchName": branch_name,
                    "ValidationResult": validation_result,
                    "DriftDetected": drift_detected,
                    "Messages": messages,
                    "Errors": errors
                }
            )
        
        config_lock_cmd = build_lock_command('config', device_type)
        config_locks = pan_client.execute_api_call({
            'type': 'op', 
            'cmd': config_lock_cmd
        })
        
        user_branch_map = {}
        if config_locks:
            for entry in config_locks.findall('.//entry'):
                user = entry.get('name')
                comment = entry.findtext('comment') or ""
                if comment:
                    clean_branch = re.sub(r'[^a-zA-Z0-9]', '-', comment)
                    user_branch_map[user] = clean_branch
        
        trigger_push = False
        target_branch = ""
        requesting_admin = "Unknown"
        commit_message = ""
        
        commit_locks = pan_client.execute_api_call({
            'type': 'op', 
            'cmd': commit_lock_cmd
        })
        
        if commit_locks:
            for entry in commit_locks.findall('.//entry'):
                admin = entry.get('name')
                comment = entry.findtext('comment') or ""
                
                if re.search(r'\bPR\b', comment, re.IGNORECASE):
                    pending_xml = pan_client.execute_api_call({
                        'type': 'op', 
                        'cmd': '<check><pending-changes></pending-changes></check>'
                    })
                    has_pending = False
                    if pending_xml and pending_xml.findtext('.//result') == 'yes':
                        has_pending = True
                    
                    if has_pending:
                        requesting_admin = admin
                        admin_name = admin
                        if admin in user_branch_map:
                            target_branch = f'{path_prefix}{user_branch_map[admin]}'
                            branch_name = target_branch
                            commit_message = f"Config modified by {admin} for {target_branch}"
                            messages.append(f"✅ Matched Trigger with Config Lock. Branch: `{target_branch}`")
                        else:
                            target_branch = f'{path_prefix}PR-automated-{admin}'
                            branch_name = target_branch
                            commit_message = f"Automated PR by {admin}"
                            messages.append(f"⚠️ No Config Lock found. Using fallback branch: `{target_branch}`")
                        
                        trigger_push = True
                        break

        # STEP 4: EXECUTION (VALIDATE -> BRANCH -> PUSH)
        if trigger_push and target_branch:
            messages.append(f"### Step 4: Processing Candidate Config")
            
            messages.append("🔍 Running Firewall Validation...")
            is_valid, val_msg = pan_client.validate_candidate_config()
            
            if not is_valid:
                validation_result = "fail"
                status = "validation_failed"
                errors.append(f"Validation failed: {val_msg}")
                messages.append(f"❌ **Validation Failed:** {val_msg}")
                messages.append("🛑 **ABORTING:** The Candidate Config is invalid.")
                messages.append("➡️ Admin must fix the configuration errors on the firewall before a PR can be created.")
                
                return CommandResults(
                    readable_output="\n".join(messages),
                    outputs_prefix="FirewallSync",
                    outputs={
                        "Status": status,
                        "AdminName": admin_name,
                        "BranchName": branch_name,
                        "ValidationResult": validation_result,
                        "DriftDetected": drift_detected,
                        "Messages": messages,
                        "Errors": errors
                    }
                )
            
            validation_result = "pass"
            messages.append("✅ Validation Passed.")
            
            # CHANGED: Use get_candidate_config
            candidate_str = pan_client.get_candidate_config()
            
            if candidate_str:
                main_sha = gh_client.get_branch_sha("main")
                
                if main_sha and gh_client.create_branch(target_branch, main_sha):
                    success = gh_client.push_file(config_path, candidate_str, commit_message, target_branch)
                    if success:
                        status = "pr_created"
                        messages.append(f"✅ **Success:** Pushed candidate config to `{target_branch}`")
                        
                        messages.append("🔒 Adding System Lock (Wait & Validate mode)...")
                        if pan_client.add_system_lock():
                            messages.append("✅ System Lock Added.")
                        else:
                            messages.append("⚠️ Failed to add System Lock.")
                            errors.append("Failed to add system lock")
                    else:
                        status = "github_push_failed"
                        errors.append("Failed to push file to GitHub")
                        messages.append("❌ Failed to push file to GitHub.")
                else:
                    status = "branch_creation_failed"
                    errors.append("Could not create branch or main SHA missing")
                    messages.append("❌ Could not create branch (or main SHA missing).")
            else:
                status = "candidate_fetch_failed"
                errors.append("Could not get candidate config")
                messages.append("❌ Could not get candidate config.")
        
        else:
            messages.append("ℹ️ No PR triggers found.")
        
    else:  # device_type == 'Panorama'
        # ========== PANORAMA: SECTIONED WORKFLOW WITH DRIFT DETECTION ==========
        messages.append("### Device Type: Panorama (Sectioned mode)")
        
        # Determine base path for sections
        if config_path:
            if '/' in config_path:
                path_parts = config_path.split('/')
                if path_parts[-1].endswith('.xml'):
                    base_path = '/'.join(path_parts[:-1])
                else:
                    base_path = config_path
            else:
                if config_path.endswith('.xml'):
                    base_path = ""
                else:
                    base_path = config_path
        else:
            base_path = ""
        
        messages.append(f"📁 **Base Path:** `{base_path or '(root)'}`")
        
        # STEP 1: CHECK IF WE'RE IN AN ACTIVE WORKFLOW
        messages.append("### Step 1: Workflow State Check")
        
        commit_lock_cmd = build_lock_command('commit', device_type)
        commit_locks = pan_client.execute_api_call({
            'type': 'op', 
            'cmd': commit_lock_cmd
        })
        
        in_active_workflow = False
        if commit_locks:
            for entry in commit_locks.findall('.//entry'):
                comment = entry.findtext('comment') or ""
                if "AUTOMATION" in comment:
                    in_active_workflow = True
                    status = "pending_approval"
                    messages.append("🔄 **Active Workflow Detected:** A PR is already pending approval.")
                    break
        
        if in_active_workflow:
            messages.append("ℹ️ Waiting for team to merge the Feature PR. No action taken.")
            return CommandResults(
                readable_output="\n".join(messages),
                outputs_prefix="FirewallSync",
                outputs={
                    "Status": status,
                    "AdminName": admin_name,
                    "BranchName": branch_name,
                    "ValidationResult": validation_result,
                    "DriftDetected": drift_detected,
                    "Messages": messages,
                    "Errors": errors
                }
            )
        
        # STEP 2: CHECK IF GITHUB STRUCTURE EXISTS
        messages.append("### Step 2: Checking GitHub Structure")
        
        structure_exists = check_github_structure_exists(gh_client, base_path)
        
        if not structure_exists:
    # ========== INITIAL SYNC MODE ==========
            messages.append("🆕 **Initial Sync Mode:** GitHub structure does not exist. Creating...")
            status = "initial_sync"
            
            # Get all sections from Panorama
            messages.append("📋 Retrieving all sections from Panorama...")
            all_sections = get_panorama_sections(pan_client)
            
            if not all_sections:
                errors.append("Failed to retrieve Panorama sections")
                return CommandResults(
                    readable_output="❌ Error: Could not retrieve Panorama sections.",
                    outputs_prefix="FirewallSync",
                    outputs={
                        "Status": "error",
                        "AdminName": admin_name,
                        "BranchName": branch_name,
                        "ValidationResult": validation_result,
                        "DriftDetected": drift_detected,
                        "Messages": messages,
                        "Errors": errors
                    }
                )
            
            total_sections = sum(len(v) for v in all_sections.values())
            messages.append(f"✅ Found {total_sections} sections: "
                        f"{len(all_sections['device-groups'])} DGs, "
                        f"{len(all_sections['templates'])} templates, "
                        f"{len(all_sections['template-stacks'])} stacks")
            
            # CRITICAL FIX: Get RUNNING config for initial sync (not candidate)
            messages.append("⬇️ Fetching running config from Panorama (current deployed state)...")
            
            # Use export_running_config() instead of get_candidate_config()
            full_config_str = pan_client.export_running_config()
            
            if not full_config_str:
                errors.append("Could not export running config")
                return CommandResults(
                    readable_output="❌ Error: Could not export running config.",
                    outputs_prefix="FirewallSync",
                    outputs={
                        "Status": "error",
                        "AdminName": admin_name,
                        "BranchName": branch_name,
                        "ValidationResult": validation_result,
                        "DriftDetected": drift_detected,
                        "Messages": messages,
                        "Errors": errors
                    }
                )
            
            messages.append(f"✅ Retrieved running config ({len(full_config_str)} characters)")
            
            # Extract and push all sections
            messages.append("🔨 Extracting all sections...")
            main_sha = gh_client.get_branch_sha("main")
            
            if not main_sha:
                errors.append("Could not get main branch SHA")
                return CommandResults(
                    readable_output="❌ Error: Could not get main branch SHA.",
                    outputs_prefix="FirewallSync",
                    outputs={
                        "Status": "error",
                        "AdminName": admin_name,
                        "BranchName": branch_name,
                        "ValidationResult": validation_result,
                        "DriftDetected": drift_detected,
                        "Messages": messages,
                        "Errors": errors
                    }
                )
            
            # Prepare all files for batch upload (more efficient than individual commits)
            files_to_push = []
            files_failed = 0

            # Extract device-groups
            demisto.debug(f"Extracting {len(all_sections['device-groups'])} device-groups...")
            for dg_name in all_sections['device-groups']:
                dg_xml = extract_section_from_config(full_config_str, 'device-group', dg_name)
                if dg_xml:
                    file_path = f"{base_path}/device-groups/{dg_name}.xml" if base_path else f"device-groups/{dg_name}.xml"
                    files_to_push.append({'path': file_path, 'content': dg_xml})
                else:
                    files_failed += 1
                    errors.append(f"Failed to extract device-group: {dg_name}")
                    demisto.error(f"Failed to extract device-group: {dg_name}")

            # Extract templates
            demisto.debug(f"Extracting {len(all_sections['templates'])} templates...")
            for tmpl_name in all_sections['templates']:
                tmpl_xml = extract_section_from_config(full_config_str, 'template', tmpl_name)
                if tmpl_xml:
                    file_path = f"{base_path}/templates/{tmpl_name}.xml" if base_path else f"templates/{tmpl_name}.xml"
                    files_to_push.append({'path': file_path, 'content': tmpl_xml})
                else:
                    files_failed += 1
                    errors.append(f"Failed to extract template: {tmpl_name}")
                    demisto.error(f"Failed to extract template: {tmpl_name}")

            # Extract template-stacks
            demisto.debug(f"Extracting {len(all_sections['template-stacks'])} template-stacks...")
            for ts_name in all_sections['template-stacks']:
                ts_xml = extract_section_from_config(full_config_str, 'template-stack', ts_name)
                if ts_xml:
                    file_path = f"{base_path}/template-stacks/{ts_name}.xml" if base_path else f"template-stacks/{ts_name}.xml"
                    files_to_push.append({'path': file_path, 'content': ts_xml})
                else:
                    files_failed += 1
                    errors.append(f"Failed to extract template-stack: {ts_name}")
                    demisto.error(f"Failed to extract template-stack: {ts_name}")

            # Extract shared objects
            demisto.debug("Extracting shared objects...")
            shared_xml = extract_section_from_config(full_config_str, 'shared', None)
            if shared_xml:
                demisto.debug(f"Shared objects extracted: {len(shared_xml)} characters")
                file_path = f"{base_path}/shared/shared.xml" if base_path else "shared/shared.xml"
                files_to_push.append({'path': file_path, 'content': shared_xml})
            else:
                files_failed += 1
                errors.append("Failed to extract shared objects")
                demisto.error("Failed to extract shared objects from running config")

            # Push all files in a SINGLE commit
            if files_to_push:
                messages.append(f"📤 Uploading {len(files_to_push)} files in a single commit...")
                if gh_client.push_multiple_files(files_to_push, "Initial sync: Panorama configuration", "main"):
                    messages.append(f"✅ **Initial Sync Complete:** Pushed {len(files_to_push)} files to GitHub in 1 commit")
                else:
                    errors.append("Failed to push files to GitHub")
                    messages.append("❌ Failed to push files to GitHub")
            else:
                messages.append("⚠️ No files to push")
            if files_failed > 0:
                messages.append(f"⚠️ **Warning:** {files_failed} files failed to push")
                messages.append("**Failed items:**")
                for error in errors:
                    messages.append(f"   - {error}")
            
            # Create snapshot for drift detection (using same running config we just used)
            messages.append("📸 Creating running config snapshot...")
            
            # We already have the running config, reuse it
            if manage_snapshot(gh_client, base_path, 'create', full_config_str, "main"):
                messages.append("✅ Snapshot created for drift detection")
            else:
                messages.append("⚠️ Warning: Failed to create snapshot (drift detection unavailable)")
            
            messages.append("ℹ️ **Next Steps:** Structure is ready. Run integration again when you have changes to create a PR.")
            

            
        else:
            # ========== INCREMENTAL UPDATE MODE ==========
            messages.append("✅ **Incremental Update Mode:** GitHub structure exists.")
            
            # STEP 2.5: DRIFT DETECTION
            messages.append("### Step 2.5: Drift Detection")
            
            # CHANGED: Use export_running_config
            current_running = pan_client.export_running_config()
            
            if current_running:
                # Get snapshot from GitHub
                snapshot_running = manage_snapshot(gh_client, base_path, 'get')
                
                if snapshot_running:
                    # Compare current vs snapshot
                    if current_running.strip() != snapshot_running.strip():
                        drift_detected = True
                        messages.append("⚠️ **DRIFT DETECTED!** Running config differs from last committed state.")
                        messages.append("🔍 **Analyzing drifted sections...**")
                        
                        # Get change list to identify drifted sections
                        change_list_root = pan_client.execute_api_call({
                            'type': 'op',
                            'cmd': '<show><config><list><changes></changes></list></config></show>'
                        })
                        
                        drifted_sections = set()
                        if change_list_root:
                            drifted_sections = parse_change_list(change_list_root)
                        
                        if not drifted_sections:
                            # Fallback: Cannot pinpoint sections
                            messages.append("⚠️ **Cannot identify specific sections** (no pending changes)")
                            messages.append("📊 **Cause:** Configuration was committed directly to firewall outside GitOps")
                            messages.append("🔧 **Action Required:** Manual review needed to identify changes")
                            
                            drift_branch = f'{path_prefix}drift-detected'
                            main_sha = gh_client.get_branch_sha("main")
                            
                            if main_sha and gh_client.create_branch(drift_branch, main_sha):
                                full_drift_path = f"{base_path}/_drift/full-running-config.xml" if base_path else "_drift/full-running-config.xml"
                                if gh_client.push_file(full_drift_path, current_running, "Drift detected: full config for manual review", drift_branch):
                                    messages.append(f"✅ Full running config saved to `{drift_branch}` for manual review")
                                    messages.append(f"📁 Path: `{full_drift_path}`")
                                    status = "drift_detected"
                                    branch_name = drift_branch
                        else:
                            # We identified specific drifted sections
                            messages.append(f"📝 **Drifted sections identified:** {len(drifted_sections)}")
                            for sec_type, sec_name in drifted_sections:
                                messages.append(f"   - {sec_type}: {sec_name or '(shared)'}")
                            
                            drift_branch = f'{path_prefix}drift-detected'
                            main_sha = gh_client.get_branch_sha("main")
                            
                            if main_sha and gh_client.create_branch(drift_branch, main_sha):
                                drift_files_pushed = 0
                                
                                for sec_type, sec_name in drifted_sections:
                                    section_xml = extract_section_from_config(current_running, sec_type, sec_name)
                                    
                                    if section_xml:
                                        if sec_type == 'device-group':
                                            folder = 'device-groups'
                                        elif sec_type == 'template':
                                            folder = 'templates'
                                        elif sec_type == 'template-stack':
                                            folder = 'template-stacks'
                                        elif sec_type == 'shared':
                                            folder = 'shared'
                                            sec_name = 'shared'
                                        else:
                                            continue
                                        
                                        file_path = f"{base_path}/{folder}/{sec_name}.xml" if base_path else f"{folder}/{sec_name}.xml"
                                        commit_msg = f"Drift detected: {sec_type} {sec_name or 'shared'}"
                                        
                                        if gh_client.push_file(file_path, section_xml, commit_msg, drift_branch):
                                            drift_files_pushed += 1
                                
                                # Also update the snapshot in drift branch to current running
                                manage_snapshot(gh_client, base_path, 'update', current_running, drift_branch)
                                
                                messages.append(f"✅ Created drift branch `{drift_branch}` with {drift_files_pushed} updated sections")
                                messages.append("ℹ️ **Action Required:** Review and merge drift branch to reconcile state")
                                status = "drift_detected"
                                branch_name = drift_branch
                        
                        messages.append("➡️ **Proceeding:** Continuing workflow despite drift detection...")
                    else:
                        messages.append("✅ No drift detected. Running config matches snapshot.")
                else:
                    messages.append("⚠️ No snapshot found. Drift detection unavailable.")
                    messages.append("💡 Snapshot will be created after next successful deployment.")
            else:
                messages.append("⚠️ Could not export running config. Skipping drift detection.")
            
            # STEP 3: GET CHANGE LIST
            messages.append("### Step 3: Analyzing Changes")
            
            change_list_root = pan_client.execute_api_call({
                'type': 'op',
                'cmd': '<show><config><list><changes></changes></list></config></show>'
            })
            
            changed_sections = set()
            if change_list_root:
                changed_sections = parse_change_list(change_list_root)
                if changed_sections:
                    messages.append(f"📝 **Changes Detected:** {len(changed_sections)} sections modified")
                    for sec_type, sec_name in changed_sections:
                        messages.append(f"   - {sec_type}: {sec_name or '(shared)'}")
            
            # STEP 4: CHECK FOR NEW SECTIONS
            messages.append("### Step 4: Checking for New Sections")
            
            all_sections = get_panorama_sections(pan_client)
            new_sections = []
            
            if all_sections:
                new_sections = detect_new_sections(all_sections, gh_client, base_path)
                if new_sections:
                    messages.append(f"🆕 **New Sections Detected:** {len(new_sections)} sections added")
                    for sec_type, sec_name in new_sections:
                        messages.append(f"   - {sec_type}: {sec_name}")
                else:
                    messages.append("✅ No new sections detected")
            
            # Combine changed and new sections
            all_affected_sections = changed_sections.union(set(new_sections))
            
            if not all_affected_sections:
                messages.append("ℹ️ **No Changes:** No sections modified or added. No action taken.")
                status = "no_changes"
            else:
                # STEP 5: CHECK FOR PR TRIGGER
                messages.append("### Step 5: Checking for PR Trigger")
                
                config_lock_cmd = build_lock_command('config', device_type)
                config_locks = pan_client.execute_api_call({
                    'type': 'op',
                    'cmd': config_lock_cmd
                })
                
                user_branch_map = {}
                if config_locks:
                    for entry in config_locks.findall('.//entry'):
                        user = entry.get('name')
                        comment = entry.findtext('comment') or ""
                        if comment:
                            clean_branch = re.sub(r'[^a-zA-Z0-9]', '-', comment)
                            user_branch_map[user] = clean_branch
                
                trigger_push = False
                target_branch = ""
                requesting_admin = "Unknown"
                
                commit_locks = pan_client.execute_api_call({
                    'type': 'op',
                    'cmd': commit_lock_cmd
                })
                
                if commit_locks:
                    for entry in commit_locks.findall('.//entry'):
                        admin = entry.get('name')
                        comment = entry.findtext('comment') or ""
                        
                        if re.search(r'\bPR\b', comment, re.IGNORECASE):
                            pending_xml = pan_client.execute_api_call({
                                'type': 'op',
                                'cmd': '<check><pending-changes></pending-changes></check>'
                            })
                            has_pending = False
                            if pending_xml and pending_xml.findtext('.//result') == 'yes':
                                has_pending = True
                            
                            if has_pending:
                                requesting_admin = admin
                                admin_name = admin
                                target_branch = f'{path_prefix}{admin}'
                                branch_name = target_branch
                                messages.append(f"✅ PR Trigger detected from admin: `{admin}`")
                                trigger_push = True
                                break
                
                if not trigger_push:
                    messages.append("ℹ️ No PR trigger found (commit lock with 'PR' comment required)")
                else:
                    # STEP 6: VALIDATION
                    messages.append("### Step 6: Validation")
                    
                    messages.append("🔍 Running Panorama Validation...")
                    is_valid, val_msg = pan_client.validate_candidate_config()
                    
                    if not is_valid:
                        validation_result = "fail"
                        status = "validation_failed"
                        errors.append(f"Validation failed: {val_msg}")
                        messages.append(f"❌ **Validation Failed:** {val_msg}")
                        messages.append("🛑 **ABORTING:** The Candidate Config is invalid.")
                        messages.append("➡️ Admin must fix the configuration errors before a PR can be created.")
                        
                        return CommandResults(
                            readable_output="\n".join(messages),
                            outputs_prefix="FirewallSync",
                            outputs={
                                "Status": status,
                                "AdminName": admin_name,
                                "BranchName": branch_name,
                                "ValidationResult": validation_result,
                                "DriftDetected": drift_detected,
                                "Messages": messages,
                                "Errors": errors
                            }
                        )
                    
                    validation_result = "pass"
                    messages.append("✅ Validation Passed.")
                    
                    # STEP 7: EXTRACT AND PUSH SECTIONS
                    messages.append("### Step 7: Extracting and Pushing Changes")
                    
                    # CHANGED: Use get_candidate_config
                    full_config_str = pan_client.get_candidate_config()
                    
                    if not full_config_str:
                        errors.append("Could not get candidate config")
                        return CommandResults(
                            readable_output="❌ Error: Could not get candidate config.",
                            outputs_prefix="FirewallSync",
                            outputs={
                                "Status": "error",
                                "AdminName": admin_name,
                                "BranchName": branch_name,
                                "ValidationResult": validation_result,
                                "DriftDetected": drift_detected,
                                "Messages": messages,
                                "Errors": errors
                            }
                        )
                    
                    # Create branch
                    main_sha = gh_client.get_branch_sha("main")
                    if not main_sha or not gh_client.create_branch(target_branch, main_sha):
                        errors.append("Could not create branch")
                        return CommandResults(
                            readable_output="❌ Error: Could not create branch.",
                            outputs_prefix="FirewallSync",
                            outputs={
                                "Status": "error",
                                "AdminName": admin_name,
                                "BranchName": branch_name,
                                "ValidationResult": validation_result,
                                "DriftDetected": drift_detected,
                                "Messages": messages,
                                "Errors": errors
                            }
                        )
                    
                    # Push each affected section
                    files_pushed = 0
                    files_failed = 0
                    failed_files_list = []  # Track which files failed

                    for sec_type, sec_name in all_affected_sections:
                        section_xml = extract_section_from_config(full_config_str, sec_type, sec_name)
                        
                        if section_xml:
                            if sec_type == 'device-group':
                                folder = 'device-groups'
                            elif sec_type == 'template':
                                folder = 'templates'
                            elif sec_type == 'template-stack':
                                folder = 'template-stacks'
                            elif sec_type == 'shared':
                                folder = 'shared'
                                sec_name = 'shared'
                            else:
                                continue
                            
                            file_path = f"{base_path}/{folder}/{sec_name}.xml" if base_path else f"{folder}/{sec_name}.xml"
                            commit_msg = f"Updated {sec_type}: {sec_name or 'shared'} by {admin_name}"
                            
                            # Log what we're about to push
                            demisto.debug(f"Pushing {file_path} ({len(section_xml)} chars) to branch {target_branch}")
                            
                            if gh_client.push_file(file_path, section_xml, commit_msg, target_branch):
                                files_pushed += 1
                                messages.append(f"   ✅ Pushed: {folder}/{sec_name}.xml")
                            else:
                                files_failed += 1
                                failed_files_list.append(f"{folder}/{sec_name}.xml")
                                errors.append(f"Failed to push: {folder}/{sec_name}.xml")
                                messages.append(f"   ❌ Failed: {folder}/{sec_name}.xml")
                        else:
                            files_failed += 1
                            failed_files_list.append(f"{sec_type}/{sec_name} (extraction failed)")
                            errors.append(f"Failed to extract {sec_type}: {sec_name}")
                            demisto.error(f"Failed to extract section: {sec_type} - {sec_name}")

                    if files_pushed > 0:
                        status = "pr_created"
                        messages.append(f"✅ **Success:** Pushed {files_pushed} files to branch `{target_branch}`")
                        
                        # Add system lock
                        messages.append("🔒 Adding System Lock...")
                        if pan_client.add_system_lock():
                            messages.append("✅ System Lock Added.")
                        else:
                            messages.append("⚠️ Failed to add System Lock.")
                            errors.append("Failed to add system lock")
                    else:
                        status = "github_push_failed"
                        messages.append("❌ All file pushes failed.")

                    if files_failed > 0:
                        messages.append(f"⚠️ **Warning:** {files_failed} files failed to push")
                        messages.append(f"**Failed files:**")
                        for failed_file in failed_files_list:
                            messages.append(f"   - {failed_file}")
                    
                    if files_pushed > 0:
                        status = "pr_created"
                        messages.append(f"✅ **Success:** Pushed {files_pushed} files to branch `{target_branch}`")
                        
                        # Add system lock
                        messages.append("🔒 Adding System Lock...")
                        if pan_client.add_system_lock():
                            messages.append("✅ System Lock Added.")
                        else:
                            messages.append("⚠️ Failed to add System Lock.")
                            errors.append("Failed to add system lock")
                    else:
                        status = "github_push_failed"
                        messages.append("❌ All file pushes failed.")
                    
                    if files_failed > 0:
                        messages.append(f"⚠️ **Warning:** {files_failed} files failed to push")
    
    # Return results
    return CommandResults(
        readable_output="\n".join(messages),
        outputs_prefix="FirewallSync",
        outputs={
            "Status": status,
            "AdminName": admin_name,
            "BranchName": branch_name,
            "ValidationResult": validation_result,
            "DriftDetected": drift_detected,
            "Messages": messages,
            "Errors": errors
        }
    )
def finalize_deployment_logic(pan_client: PanOsClient, gh_client: GitHubClient, config_path: str, device_type: str) -> CommandResults:
    """
    Post-Merge Workflow:
    - For Firewalls: Single-file verification
    - For Panorama: Sectioned verification + snapshot update
    1. Verify Main == Candidate (Safety Check)
    2. Smart Unlock (Find Admin -> Remove by Admin)
    3. Update Snapshot (Panorama only)
    4. (Optional) Commit to Firewall
    """
    messages = []
    
    # Output tracking variables
    status = "no_action"
    unlock_success = False
    admin_unlocked = None
    safety_check_passed = False
    errors = []
    
    messages.append("### Finalizing Deployment")

    # ==========================================
    # DEVICE TYPE ROUTING
    # ==========================================
    if device_type == 'Firewall':
        # ========== FIREWALL: SINGLE-FILE VERIFICATION ==========
        messages.append("### Device Type: Firewall (Single-file mode)")

        # Determine base path for snapshots (same as sync workflow)
        if config_path:
            if '/' in config_path:
                path_parts = config_path.split('/')
                if path_parts[-1].endswith('.xml'):
                    base_path = '/'.join(path_parts[:-1])
                else:
                    base_path = config_path
            else:
                if config_path.endswith('.xml'):
                    base_path = ""
                else:
                    base_path = config_path
        else:
            base_path = ""
        
        # 1. FETCH CONFIGS
        messages.append("⬇️ Fetching 'main' from GitHub...")
        gh_content = gh_client.get_file_content(config_path, "main")

        messages.append("⬇️ Fetching Candidate Config from Firewall...")
        
        # CHANGED: Use get_candidate_config
        fw_candidate = pan_client.get_candidate_config()

        if not gh_content or not fw_candidate:
            status = "error"
            errors.append("Could not fetch configurations for comparison")
            return CommandResults(
                readable_output="❌ Error: Could not fetch configurations for comparison.",
                outputs_prefix="FirewallSync.Finalize",
                outputs={
                    "Status": status,
                    "UnlockSuccess": unlock_success,
                    "AdminUnlocked": admin_unlocked,
                    "SafetyCheckPassed": safety_check_passed,
                    "Messages": messages,
                    "Errors": errors
                }
            )

        # 2. DIFF CHECK (Simple String Comparison)
        if gh_content.strip() == fw_candidate.strip():
            safety_check_passed = True
            messages.append("✅ **Safety Check Passed:** Firewall Candidate matches GitHub Main.")
        else:
            status = "diff_detected"
            errors.append("GitHub Main does NOT match Firewall Candidate")
            messages.append("⚠️ **Diff Detected:** GitHub Main does NOT match Firewall Candidate.")
            messages.append("🛑 **ABORTING:** Risk of overwriting unknown changes. Please verify manually.")
            return CommandResults(
                readable_output="\n".join(messages),
                outputs_prefix="FirewallSync.Finalize",
                outputs={
                    "Status": status,
                    "UnlockSuccess": unlock_success,
                    "AdminUnlocked": admin_unlocked,
                    "SafetyCheckPassed": safety_check_passed,
                    "Messages": messages,
                    "Errors": errors
                }
            )

        # 3. UNLOCK (SMART CHECK)
        messages.append("🔓 Checking System Locks...")

        commit_lock_cmd = build_lock_command('commit', device_type)
        lock_root = pan_client.execute_api_call({'type': 'op', 'cmd': commit_lock_cmd})

        lock_found = False
        admin_to_unlock = None

        if lock_root:
            for entry in lock_root.findall('.//entry'):
                comment = entry.findtext('comment') or ""
                if "AUTOMATION" in comment:
                    admin_to_unlock = entry.get('name')
                    admin_unlocked = admin_to_unlock
                    lock_found = True
                    break

        if lock_found and admin_to_unlock:
            messages.append(f"🔒 Automation Lock found (User: {admin_to_unlock}). Removing...")

            unlock_cmd = {'type': 'op', 'cmd': f'<request><commit-lock><remove><admin>{admin_to_unlock}</admin></remove></commit-lock></request>'}
            unlock_res = pan_client.execute_api_call(unlock_cmd)

            if unlock_res is not None:
                resp_str = ET.tostring(unlock_res, encoding='unicode').lower()
                if 'success' in resp_str or 'removed' in resp_str:
                    unlock_success = True
                    status = "unlocked"
                    messages.append("✅ System Unlocked.")
                else:
                    status = "unlock_failed"
                    errors.append(f"API returned unexpected response: {resp_str}")
                    messages.append(f"⚠️ API returned generic response: {resp_str}")
            else:
                status = "unlock_failed"
                errors.append("Failed to remove lock - API call failed")
                messages.append("❌ Error: Failed to remove lock. API call failed.")

        elif lock_found and not admin_to_unlock:
            status = "unlock_failed"
            errors.append("Lock found but could not parse Admin Name")
            messages.append("❌ Error: Lock found but could not parse Admin Name.")

        else:
            unlock_success = True
            status = "already_unlocked"
            messages.append("✅ No automation lock found (already removed).")

        # 4. UPDATE SNAPSHOT
        if safety_check_passed and unlock_success:
            messages.append("### Step 4: Updating Snapshot")
            messages.append("📸 Updating running config snapshot...")

            # Get current running config from firewall
            running_config_str = pan_client.export_running_config()

            if running_config_str:
                if manage_snapshot(gh_client, base_path, 'update', running_config_str, "main"):
                    messages.append("✅ Snapshot updated for drift detection")
                else:
                    messages.append("⚠️ Warning: Failed to update snapshot")
                    errors.append("Failed to update snapshot")
            else:
                messages.append("⚠️ Warning: Could not export running config for snapshot update")
                errors.append("Could not export running config")

        # 5. COMMIT (OPTIONAL - COMMENTED OUT)
        """
        messages.append("💾 Committing to Firewall...")
        commit_cmd = {'type': 'commit', 'cmd': '<commit></commit>'}
        commit_root = pan_client.execute_api_call(commit_cmd)
        """

        # Final status if everything succeeded
        if status not in ["error", "diff_detected", "unlock_failed"]:
            status = "complete"

        messages.append("ℹ️ **Process Complete:** Deployment ready for manual commit (or enable auto-commit).")
    
    else:  # device_type == 'Panorama'
        # ========== PANORAMA: SECTIONED VERIFICATION + SNAPSHOT UPDATE ==========
        messages.append("### Device Type: Panorama (Sectioned mode)")
        
        # Determine base path
        if config_path:
            if '/' in config_path:
                path_parts = config_path.split('/')
                if path_parts[-1].endswith('.xml'):
                    base_path = '/'.join(path_parts[:-1])
                else:
                    base_path = config_path
            else:
                if config_path.endswith('.xml'):
                    base_path = ""
                else:
                    base_path = config_path
        else:
            base_path = ""
        
        messages.append(f"📁 **Base Path:** `{base_path or '(root)'}`")
        
        # 1. IDENTIFY CHANGED SECTIONS
        messages.append("### Step 1: Identifying Changed Sections")
        messages.append("🔍 Analyzing what sections were merged...")
        
        change_list_root = pan_client.execute_api_call({
            'type': 'op',
            'cmd': '<show><config><list><changes></changes></list></config></show>'
        })
        
        changed_sections = set()
        if change_list_root:
            changed_sections = parse_change_list(change_list_root)
        
        all_sections = get_panorama_sections(pan_client)
        if all_sections:
            new_sections = detect_new_sections(all_sections, gh_client, base_path)
            changed_sections = changed_sections.union(set(new_sections))
        
        if changed_sections:
            messages.append(f"📝 **Sections to verify:** {len(changed_sections)}")
            for sec_type, sec_name in changed_sections:
                messages.append(f"   - {sec_type}: {sec_name or '(shared)'}")
        else:
            messages.append("⚠️ **Warning:** No changed sections detected. Verification may be incomplete.")
        
        # 2. FETCH CANDIDATE CONFIG
        messages.append("### Step 2: Fetching Candidate Config")
        messages.append("⬇️ Fetching Candidate Config from Panorama...")
        
        # CHANGED: Use get_candidate_config
        full_candidate_str = pan_client.get_candidate_config()
        
        if not full_candidate_str:
            status = "error"
            errors.append("Could not get candidate config")
            return CommandResults(
                readable_output="❌ Error: Could not get candidate config.",
                outputs_prefix="FirewallSync.Finalize",
                outputs={
                    "Status": status,
                    "UnlockSuccess": unlock_success,
                    "AdminUnlocked": admin_unlocked,
                    "SafetyCheckPassed": safety_check_passed,
                    "Messages": messages,
                    "Errors": errors
                }
            )
        
        messages.append("✅ Candidate config retrieved")
        
        # 3. VERIFY EACH SECTION
        messages.append("### Step 3: Safety Check - Verifying Sections")
        
        sections_verified = 0
        sections_failed = 0
        
        for sec_type, sec_name in changed_sections:
            if sec_type == 'device-group':
                folder = 'device-groups'
            elif sec_type == 'template':
                folder = 'templates'
            elif sec_type == 'template-stack':
                folder = 'template-stacks'
            elif sec_type == 'shared':
                folder = 'shared'
                sec_name = 'shared'
            else:
                continue
            
            file_path = f"{base_path}/{folder}/{sec_name}.xml" if base_path else f"{folder}/{sec_name}.xml"
            
            gh_section = gh_client.get_file_content(file_path, "main")
            fw_section = extract_section_from_config(full_candidate_str, sec_type, sec_name if sec_type != 'shared' else None)
            
            if gh_section and fw_section:
                if gh_section.strip() == fw_section.strip():
                    sections_verified += 1
                    messages.append(f"   ✅ {folder}/{sec_name}.xml - Match")
                else:
                    sections_failed += 1
                    errors.append(f"Mismatch: {folder}/{sec_name}.xml")
                    messages.append(f"   ❌ {folder}/{sec_name}.xml - MISMATCH")
            else:
                sections_failed += 1
                errors.append(f"Could not retrieve/extract: {folder}/{sec_name}.xml")
                messages.append(f"   ⚠️ {folder}/{sec_name}.xml - Could not verify")
        
        if sections_failed > 0:
            safety_check_passed = False
            status = "diff_detected"
            messages.append(f"⚠️ **Safety Check Failed:** {sections_failed} section(s) do not match")
            messages.append("🛑 **ABORTING:** Risk of overwriting unknown changes. Please verify manually.")
            return CommandResults(
                readable_output="\n".join(messages),
                outputs_prefix="FirewallSync.Finalize",
                outputs={
                    "Status": status,
                    "UnlockSuccess": unlock_success,
                    "AdminUnlocked": admin_unlocked,
                    "SafetyCheckPassed": safety_check_passed,
                    "Messages": messages,
                    "Errors": errors
                }
            )
        else:
            safety_check_passed = True
            messages.append(f"✅ **Safety Check Passed:** All {sections_verified} section(s) match GitHub Main")
        
        # 4. UNLOCK
        messages.append("### Step 4: Removing System Lock")
        messages.append("🔓 Checking System Locks...")

        commit_lock_cmd = build_lock_command('commit', device_type)
        lock_root = pan_client.execute_api_call({'type': 'op', 'cmd': commit_lock_cmd})

        lock_found = False
        admin_to_unlock = None

        if lock_root:
            for entry in lock_root.findall('.//entry'):
                comment = entry.findtext('comment') or ""
                if "AUTOMATION" in comment:
                    admin_to_unlock = entry.get('name')
                    admin_unlocked = admin_to_unlock
                    lock_found = True
                    break

        if lock_found and admin_to_unlock:
            messages.append(f"🔒 Automation Lock found (User: {admin_to_unlock}). Removing...")

            unlock_cmd = {'type': 'op', 'cmd': f'<request><commit-lock><remove><admin>{admin_to_unlock}</admin></remove></commit-lock></request>'}
            unlock_res = pan_client.execute_api_call(unlock_cmd)

            if unlock_res is not None:
                resp_str = ET.tostring(unlock_res, encoding='unicode').lower()
                if 'success' in resp_str or 'removed' in resp_str:
                    unlock_success = True
                    status = "unlocked"
                    messages.append("✅ System Unlocked.")
                else:
                    status = "unlock_failed"
                    errors.append(f"API returned unexpected response: {resp_str}")
                    messages.append(f"⚠️ API returned generic response: {resp_str}")
            else:
                status = "unlock_failed"
                errors.append("Failed to remove lock - API call failed")
                messages.append("❌ Error: Failed to remove lock. API call failed.")

        elif lock_found and not admin_to_unlock:
            status = "unlock_failed"
            errors.append("Lock found but could not parse Admin Name")
            messages.append("❌ Error: Lock found but could not parse Admin Name.")

        else:
            unlock_success = True
            status = "already_unlocked"
            messages.append("✅ No automation lock found (already removed).")
        
        # 5. UPDATE SNAPSHOT
        if safety_check_passed and unlock_success:
            messages.append("### Step 5: Updating Snapshot")
            messages.append("📸 Updating running config snapshot...")
            
            # CHANGED: Use export_running_config
            running_config_str = pan_client.export_running_config()
            
            if running_config_str:
                if manage_snapshot(gh_client, base_path, 'update', running_config_str, "main"):
                    messages.append("✅ Snapshot updated for drift detection")
                else:
                    messages.append("⚠️ Warning: Failed to update snapshot")
                    errors.append("Failed to update snapshot")
            else:
                messages.append("⚠️ Warning: Could not export running config for snapshot update")
                errors.append("Could not export running config")
        
        # 6. COMMIT (OPTIONAL - COMMENTED OUT)
        """
        messages.append("💾 Committing to Panorama...")
        commit_cmd = {'type': 'commit', 'cmd': '<commit></commit>'}
        commit_root = pan_client.execute_api_call(commit_cmd)
        """

        # Final status if everything succeeded
        if status not in ["error", "diff_detected", "unlock_failed"]:
            status = "complete"

        messages.append("ℹ️ **Process Complete:** Deployment ready for manual commit (or enable auto-commit).")

    return CommandResults(
        readable_output="\n".join(messages),
        outputs_prefix="FirewallSync.Finalize",
        outputs={
            "Status": status,
            "UnlockSuccess": unlock_success,
            "AdminUnlocked": admin_unlocked,
            "SafetyCheckPassed": safety_check_passed,
            "Messages": messages,
            "Errors": errors
        }
    )
def fetch_incidents(gh_client, config_path):
    """
    Called every X minutes by XSOAR to check for new commits.
    """
    # 1. Retrieve the last known state
    last_run = demisto.getLastRun()
    last_sha = last_run.get('last_sha')
    processed_shas = last_run.get('processed_shas', [])

    # 2. Check GitHub for current state
    commit_info = gh_client.get_latest_commit_details("main")

    incidents = []

    if commit_info:
        current_sha = commit_info['sha']

        # 3. Detect Change
        if last_sha and current_sha != last_sha and current_sha not in processed_shas:
            demisto.debug(f"New commit detected: {current_sha}")
            incidents.append({
                'name': f"Firewall Sync: Merge Detected ({current_sha[:7]})",
                'occurred': commit_info['date'],
                'rawJSON': json.dumps(commit_info),
                'type': 'Firewall Ops',
                'severity': 2,
                'CustomFields': {
                    'commitsha': current_sha,
                    'author': commit_info['author']
                }
            })

            processed_shas.append(current_sha)
            # Keep only last 50 SHAs to prevent unbounded growth
            processed_shas = processed_shas[-50:]

        # 4. Save the new state
        demisto.setLastRun({
            'last_sha': current_sha,
            'processed_shas': processed_shas
        })

    return incidents


#Helper function
def get_integration_context():
    """Retrieve persistent integration context"""
    return demisto.getIntegrationContext()

def set_integration_context(context):
    """Save persistent integration context"""
    demisto.setIntegrationContext(context)


def test_github_connectivity(gh_client: GitHubClient, base_path: str) -> CommandResults:
    """
    Test GitHub connectivity and permissions.
    Tests: read access, write access, branch operations.
    """
    messages = []
    tests_passed = 0
    tests_failed = 0
    
    messages.append("### GitHub Connectivity Test")
    messages.append(f"📁 **Testing with base path:** `{base_path or '(root)'}`")
    messages.append("")
    
    # TEST 1: Check main branch exists
    messages.append("**Test 1: Get Main Branch SHA**")
    try:
        main_sha = gh_client.get_branch_sha("main")
        if main_sha:
            messages.append(f"   ✅ PASS - Main branch SHA: {main_sha[:7]}")
            tests_passed += 1
        else:
            messages.append("   ❌ FAIL - Could not get main branch SHA")
            tests_failed += 1
    except Exception as e:
        messages.append(f"   ❌ FAIL - Exception: {str(e)}")
        tests_failed += 1
    
    messages.append("")
    
    # TEST 2: Check if we can read from repo
    messages.append("**Test 2: Read Repository Content**")
    try:
        # Try to read README or any file
        content = gh_client.get_file_content("README.md", "main")
        if content:
            messages.append(f"   ✅ PASS - Successfully read README.md ({len(content)} chars)")
            tests_passed += 1
        else:
            # README might not exist, try root listing
            url = gh_client.base_url
            res = requests.get(url, headers=gh_client.headers, params={"ref": "main"})
            if res.status_code == 200:
                messages.append(f"   ✅ PASS - Can read repository root")
                tests_passed += 1
            else:
                messages.append(f"   ❌ FAIL - Cannot read repository (status: {res.status_code})")
                tests_failed += 1
    except Exception as e:
        messages.append(f"   ❌ FAIL - Exception: {str(e)}")
        tests_failed += 1
    
    messages.append("")
    
    # TEST 3: Check write permissions (create a test file)
    messages.append("**Test 3: Write Permission Test**")
    test_file_path = f"{base_path}/_test/connectivity-test.txt" if base_path else "_test/connectivity-test.txt"
    test_content = f"Connectivity test at {time.time()}"
    
    try:
        success = gh_client.push_file(test_file_path, test_content, "Test: Connectivity check", "main")
        if success:
            messages.append(f"   ✅ PASS - Successfully wrote test file: {test_file_path}")
            tests_passed += 1
            
            # Clean up test file
            messages.append(f"   🧹 Cleaning up test file...")
            # Note: We don't have a delete method, so we'll leave it
            messages.append(f"   ℹ️  Test file left at: {test_file_path} (please delete manually if desired)")
        else:
            messages.append(f"   ❌ FAIL - Could not write test file (check logs for details)")
            tests_failed += 1
    except Exception as e:
        messages.append(f"   ❌ FAIL - Exception: {str(e)}")
        tests_failed += 1
    
    messages.append("")
    
    # TEST 4: Check branch creation
    messages.append("**Test 4: Branch Creation Test**")
    test_branch_name = f"test-connectivity-{int(time.time())}"
    
    try:
        main_sha = gh_client.get_branch_sha("main")
        if main_sha:
            success = gh_client.create_branch(test_branch_name, main_sha)
            if success:
                messages.append(f"   ✅ PASS - Successfully created test branch: {test_branch_name}")
                messages.append(f"   ℹ️  Test branch created (can be deleted manually)")
                tests_passed += 1
            else:
                messages.append(f"   ❌ FAIL - Could not create test branch")
                tests_failed += 1
        else:
            messages.append(f"   ⚠️  SKIP - Cannot test (no main SHA)")
    except Exception as e:
        messages.append(f"   ❌ FAIL - Exception: {str(e)}")
        tests_failed += 1
    
    messages.append("")
    messages.append("---")
    messages.append(f"**Test Results:** {tests_passed} passed, {tests_failed} failed")
    
    if tests_failed == 0:
        messages.append("✅ **All tests passed!** GitHub connectivity is working correctly.")
        status = "success"
    else:
        messages.append("⚠️ **Some tests failed.** Check the logs and verify:")
        messages.append("   1. GitHub token has 'repo' scope (full repository access)")
        messages.append("   2. Repository owner and name are correct")
        messages.append("   3. Network connectivity to GitHub is working")
        status = "failed"
    
    return CommandResults(
        readable_output="\n".join(messages),
        outputs_prefix="FirewallSync.ConnectivityTest",
        outputs={
            "Status": status,
            "TestsPassed": tests_passed,
            "TestsFailed": tests_failed,
            "Messages": messages
        }
    )


''' MAIN ENTRY POINT '''

def test_module(pan_client, gh_client):
    """Connectivity test for Integration settings page"""
    try:
        # Test Firewall
        cmd = {'type': 'op', 'cmd': '<show><system><info></info></system></show>'}
        if not pan_client.execute_api_call(cmd):
            return 'Failed to connect to Panorama.'

        # Test GitHub
        if not gh_client.get_branch_sha('main'):
            return 'Failed to connect to GitHub (Main SHA not found).'

        return 'ok'
    except Exception as e:
        return f'Test failed: {str(e)}'

def main():
    try:
        # 1. Get Settings (Params)
        params = demisto.params()
        pan_host = params.get('panorama_host')
        pan_key = params.get('panorama_apikey')
        gh_token = params.get('github_token')
        repo_owner = params.get('repo_owner')
        repo_name = params.get('repo_name')
        verify_ssl = not params.get('insecure', False)
        
        # Get config path with default
        config_path = params.get('config_path', 'firewall_config.xml').strip()
        if not config_path:
            config_path = 'firewall_config.xml'
        
        # Get device type with default
        device_type = params.get('device_type', 'Panorama').strip()
        if device_type not in ['Panorama', 'Firewall']:
            device_type = 'Panorama'

        # 2. Initialize Clients
        pan_client = PanOsClient(pan_host, pan_key, verify_ssl)
        gh_client = GitHubClient(gh_token, repo_owner, repo_name)

        # 3. Route Commands
        command = demisto.command()

        if command == 'test-module':
            return_results(test_module(pan_client, gh_client))

        elif command == 'fetch-incidents':
            incidents = fetch_incidents(gh_client, config_path)
            demisto.incidents(incidents)

        elif command == 'firewall-git-sync':
            return_results(sync_firewall_logic(pan_client, gh_client, config_path, device_type))

        elif command == 'firewall-git-finalize':
            return_results(finalize_deployment_logic(pan_client, gh_client, config_path, device_type))
        
        # NEW: Debug connectivity test
        elif command == 'firewall-git-test-connectivity':
            # Determine base_path same way as in sync logic
            if config_path:
                if '/' in config_path:
                    path_parts = config_path.split('/')
                    if path_parts[-1].endswith('.xml'):
                        base_path = '/'.join(path_parts[:-1])
                    else:
                        base_path = config_path
                else:
                    if config_path.endswith('.xml'):
                        base_path = ""
                    else:
                        base_path = config_path
            else:
                base_path = ""
            
            return_results(test_github_connectivity(gh_client, base_path))

    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command. Error: {str(e)}")

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()