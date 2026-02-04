import asyncio
import os
import re
import aiofiles
import httpx
from typing import List, Dict, Set, Tuple, Optional
import tempfile
import shutil
from git import Repo
from git.exc import GitCommandError
from datetime import datetime  # Make sure this is imported
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class GitHubScanner:
    def __init__(self):
        self.github_token = os.getenv("GITHUB_TOKEN")
        self.max_file_size = int(os.getenv("MAX_FILE_SIZE_MB", "5")) * 1024 * 1024
        self.skip_extensions = os.getenv("SKIP_EXTENSIONS", ".exe,.dll,.so,.dylib,.jpg,.png,.gif,.pdf,.zip,.tar.gz,.tgz").split(",")
        
        # Enhanced secret patterns
        self.secret_patterns = {
            'aws_access_key': r'AKIA[0-9A-Z]{16}',
            'aws_secret_key': r'(?i)aws[_-]?secret[_-]?access[_-]?key[=\s:]+[\'"]([A-Za-z0-9/+]{40})[\'"]',
            'aws_session_token': r'(?i)aws[_-]?session[_-]?token[=\s:]+[\'"]([A-Za-z0-9/+]{340,})[\'"]',
            'api_key': r'(?i)(api[_-]?key|secret[_-]?key)[=\s:]+[\'"]([A-Za-z0-9_\-]{32,})[\'"]',
            'password': r'(?i)(password|passwd|pwd)[=\s:]+[\'"]([^\s\'"\n]{6,})[\'"]',
            'bearer_token': r'Bearer\s+([A-Za-z0-9\-._~+/]+=*)',
            'jwt_token': r'eyJ[A-Za-z0-9\-._~+/]+=*\.eyJ[A-Za-z0-9\-._~+/]+=*(?:\.[A-Za-z0-9\-._~+/]+=*)?',
            'github_token': r'gh[pousr]_[A-Za-z0-9_]{36,}',
            'slack_token': r'xox[baprs]-[0-9a-zA-Z]{10,48}',
            'firebase': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
            'heroku_api': r'[hH]eroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
            'mailgun_api': r'key-[0-9a-zA-Z]{32}',
            'stripe_api': r'sk_live_[0-9a-zA-Z]{24}',
            'stripe_pub_key': r'pk_live_[0-9a-zA-Z]{24}',
            'twilio_api': r'SK[0-9a-fA-F]{32}',
            'twilio_account_sid': r'AC[0-9a-fA-F]{32}',
            'database_url': r'(?i)(mysql|postgresql|mongodb)://[^\s"\']+',
            'private_ssh_key': r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
            'private_rsa_key': r'-----BEGIN RSA PRIVATE KEY-----',
            'google_api': r'AIza[0-9A-Za-z\-_]{35}',
            'google_oauth': r'ya29\.[0-9A-Za-z\-_]+',
            'facebook_token': r'EAACEdEose0cBA[0-9A-Za-z]+',
            #'instagram_token': r'IG[0-9A-Za-z\-_\.]+',
        }
        
        # Enhanced bucket patterns
        self.bucket_patterns = {
            'aws_s3': r'([a-z0-9\-\.]+)\.s3(?:-[a-z0-9\-]+)?\.amazonaws\.com',
            'aws_s3_url': r's3://([a-z0-9\-\.]+)/[^\s"\']*',
            'aws_s3_arn': r'arn:aws:s3:::([a-z0-9\-\.]+)',
            'gcp_bucket': r'storage\.cloud\.google\.com/([a-z0-9\-_\.]+)',
            'gcp_storage': r'([a-z0-9\-_\.]+)\.storage\.googleapis\.com',
            'azure_blob': r'([a-z0-9\-]+)\.blob\.core\.windows\.net',
            'azure_storage': r'DefaultEndpointsProtocol=https;AccountName=([a-z0-9]+);',
            'digitalocean': r'([a-z0-9\-]+)\.([a-z0-9\-]+)\.digitaloceanspaces\.com',
            'backblaze': r'([a-z0-9\-]+)\.s3\.backblazeb2\.com',
            'cloudflare': r'([a-z0-9\-]+)\.r2\.cloudflarestorage\.com',
        }
    
    async def detect_account_type(self, account_name: str) -> Tuple[str, str]:
        """Detect if account is an organization or user"""
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "GitHub-Security-Scanner"
        }
        
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Try organization first
            org_url = f"https://api.github.com/orgs/{account_name}"
            user_url = f"https://api.github.com/users/{account_name}"
            
            # Check if it's an organization
            try:
                response = await client.get(org_url, headers=headers)
                if response.status_code == 200:
                    return "organization", org_url
            except:
                pass
            
            # Check if it's a user
            try:
                response = await client.get(user_url, headers=headers)
                if response.status_code == 200:
                    return "user", user_url
            except:
                pass
            
            # If we can't determine, default to user API
            return "unknown", user_url
    
    async def get_github_repos(self, account_name: str, scan_type: str = "public") -> List[Dict]:
        """Fetch repositories from GitHub (works for both orgs and users)"""
        repos = []
        
        # Detect account type
        account_type, base_url = await self.detect_account_type(account_name)
        print(f"Detected account type: {account_type}")
        
        if account_type == "organization":
            repos_url = f"{base_url}/repos"
        else:  # user or unknown
            repos_url = f"https://api.github.com/users/{account_name}/repos"
        
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "GitHub-Security-Scanner"
        }
        
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"
            print(f"Using GitHub token (last 4 chars: {self.github_token[-4:]})")
        else:
            print("Warning: No GitHub token provided. Rate limited to 60 requests/hour")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            page = 1
            while True:
                try:
                    params = {
                        "page": page, 
                        "per_page": 100,
                        "sort": "updated",
                        "direction": "desc"
                    }
                    
                    response = await client.get(repos_url, headers=headers, params=params)
                    
                    if response.status_code == 403:
                        error_msg = "GitHub API rate limit exceeded"
                        if not self.github_token:
                            error_msg += ". Add GITHUB_TOKEN to .env file for higher limits."
                        print(error_msg)
                        break
                    elif response.status_code == 404:
                        print(f"Account '{account_name}' not found")
                        break
                    elif response.status_code == 401:
                        print("Invalid or expired GitHub token")
                        break
                    
                    response.raise_for_status()
                    
                    batch = response.json()
                    if not batch:
                        break
                    
                    for repo in batch:
                        # Apply filters based on scan type
                        include = False
                        
                        if scan_type == "all":
                            include = True
                        elif scan_type == "public" and not repo.get("private"):
                            include = True
                        elif scan_type == "private" and repo.get("private"):
                            include = True
                        elif scan_type == "forked" and repo.get("fork"):
                            include = True
                        elif scan_type == "archived" and repo.get("archived"):
                            include = True
                        elif scan_type == "source" and not repo.get("fork"):
                            include = True
                        
                        if include:
                            repos.append({
                                "id": repo["id"],
                                "name": repo["name"],
                                "full_name": repo["full_name"],
                                "clone_url": repo["clone_url"],
                                "ssh_url": repo.get("ssh_url", ""),
                                "fork": repo.get("fork", False),
                                "archived": repo.get("archived", False),
                                "private": repo.get("private", False),
                                "size": repo.get("size", 0),
                                "updated_at": repo.get("updated_at", ""),
                                "stars": repo.get("stargazers_count", 0),
                                "forks": repo.get("forks_count", 0),
                                "account_type": account_type
                            })
                    
                    print(f"Fetched page {page} with {len(batch)} repos")
                    page += 1
                    
                    # Check if we should continue
                    links = response.headers.get("link", "")
                    if 'rel="next"' not in links:
                        break
                    
                    # Safety limit
                    if page > 10:  # Max 1000 repos
                        print("Reached maximum pages (1000 repos)")
                        break
                        
                except httpx.HTTPStatusError as e:
                    print(f"HTTP error fetching repos: {e}")
                    break
                except Exception as e:
                    print(f"Error fetching repos: {e}")
                    break
        
        print(f"Total repositories found: {len(repos)}")
        return repos
    
    def should_skip_file(self, file_path: str, file_size: int) -> bool:
        """Check if file should be skipped based on extension or size"""
        # Skip large files
        if file_size > self.max_file_size:
            return True
        
        # Skip based on extension
        file_ext = os.path.splitext(file_path)[1].lower()
        if file_ext in self.skip_extensions:
            return True
        
        # Skip common binary/irrelevant files
        skip_patterns = [
            '.git/', '__pycache__/', 'node_modules/', 'vendor/', 
            '.DS_Store', '.min.js', '.min.css', 'package-lock.json',
            'yarn.lock', '.log', '.ico', '.woff', '.woff2', '.ttf', '.eot'
        ]
        for pattern in skip_patterns:
            if pattern in file_path:
                return True
        
        return False
    
    async def clone_repository(self, repo_url: str, temp_dir: str) -> Optional[str]:
        """Clone a repository to temporary directory (shallow clone for latest code only)"""
        repo_name = repo_url.split("/")[-1].replace(".git", "")
        repo_path = os.path.join(temp_dir, repo_name)
        
        try:
            # Use token in URL if available for private repos
            if self.github_token and "github.com" in repo_url:
                # Replace https:// with https://token@
                auth_url = repo_url.replace(
                    "https://",
                    f"https://{self.github_token}@"
                )
            else:
                auth_url = repo_url
            
            print(f"Cloning {repo_name} (shallow clone)...")
            
            # Shallow clone - only get latest commit (depth=1)
            Repo.clone_from(
                auth_url, 
                repo_path, 
                depth=1,  # Shallow clone - only latest commit
                single_branch=True,  # Only clone default branch
                progress=None
            )
            
            print(f"✓ Successfully cloned {repo_name}")
            return repo_path
            
        except GitCommandError as e:
            print(f"✗ Failed to clone {repo_url}: {e}")
            
            # Try without auth as fallback (for public repos)
            if self.github_token:  # Only try without auth if we tried with auth
                try:
                    print(f"Trying without authentication for {repo_name}...")
                    Repo.clone_from(
                        repo_url, 
                        repo_path, 
                        depth=1,
                        single_branch=True,
                        progress=None
                    )
                    print(f"✓ Successfully cloned {repo_name} without auth")
                    return repo_path
                except GitCommandError as e2:
                    print(f"✗ Failed to clone {repo_name} even without auth: {e2}")
            
            return None
    
    async def scan_file_for_secrets(self, file_path: str) -> List[Dict]:
        """Scan a single file for secrets"""
        findings = []
        
        try:
            file_size = os.path.getsize(file_path)
            if self.should_skip_file(file_path, file_size):
                return findings
            
            async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = await f.read()
                
            for secret_type, pattern in self.secret_patterns.items():
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    # Get context (2 lines before and after)
                    lines = content.split('\n')
                    match_line_num = content[:match.start()].count('\n')
                    start_line = max(0, match_line_num - 2)
                    end_line = min(len(lines), match_line_num + 3)
                    context_lines = lines[start_line:end_line]
                    
                    # Highlight the matching line
                    if 0 <= match_line_num - start_line < len(context_lines):
                        context_lines[match_line_num - start_line] = f"🔍 {context_lines[match_line_num - start_line]}"
                    
                    context = '\n'.join(context_lines)
                    
                    # Mask the secret value for security
                    secret_value = match.group()
                    masked_value = secret_value[:4] + "..." + secret_value[-4:] if len(secret_value) > 10 else "***"
                    
                    # Determine severity
                    severity = "medium"
                    if secret_type in ['aws_secret_key', 'github_token', 'private_ssh_key', 'stripe_api']:
                        severity = "critical"
                    elif secret_type in ['aws_access_key', 'jwt_token', 'database_url']:
                        severity = "high"
                    
                    findings.append({
                        "type": secret_type,
                        "severity": severity,
                        "value": masked_value,
                        "full_value": secret_value,  # Store full value for verification
                        "file": os.path.basename(file_path),
                        "file_path": file_path,
                        "line": match_line_num + 1,
                        "context": context[:1000],  # Limit context length
                        "timestamp": datetime.now().isoformat()
                    })
                    
        except (UnicodeDecodeError, IsADirectoryError, PermissionError, OSError) as e:
            # Skip files we can't read
            pass
        
        return findings
    
    async def scan_repository(self, repo_path: str) -> Tuple[List[Dict], Set[Tuple[str, str]]]:
        """Scan a repository for secrets and bucket URLs"""
        secrets = []
        bucket_urls = set()
        
        total_files = 0
        scanned_files = 0
        
        for root, dirs, files in os.walk(repo_path):
            # Skip common directories
            skip_dirs = ['.git', '__pycache__', 'node_modules', 'vendor', 'dist', 'build', '.next', '.nuxt']
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            
            for file in files:
                total_files += 1
                file_path = os.path.join(root, file)
                
                # Scan for secrets
                file_secrets = await self.scan_file_for_secrets(file_path)
                secrets.extend(file_secrets)
                
                # Extract bucket URLs (only if file is readable)
                try:
                    file_size = os.path.getsize(file_path)
                    if not self.should_skip_file(file_path, file_size):
                        async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = await f.read()
                            
                        for bucket_type, pattern in self.bucket_patterns.items():
                            matches = re.finditer(pattern, content, re.IGNORECASE)
                            for match in matches:
                                bucket_url = match.group()
                                # Clean up the bucket URL
                                if bucket_url.startswith('s3://'):
                                    bucket_url = bucket_url.split('/')[2] if '/' in bucket_url else bucket_url
                                bucket_urls.add((bucket_url, bucket_type))
                                
                        scanned_files += 1
                except:
                    continue
        
        print(f"Scanned {scanned_files}/{total_files} files in {os.path.basename(repo_path)}")
        return secrets, bucket_urls
    
    async def scan_secrets_only(self, account_name: str, scan_type: str) -> Dict:
        """Scan repositories for secrets only (first phase)"""
        findings = {
            "secrets": [],
            "stats": {
                "total_repos": 0,
                "scanned_repos": 0,
                "secrets_found": 0,
                "bucket_urls_found": 0,
                "total_files_scanned": 0
            },
            "bucket_urls": []  # Store raw bucket URLs for second phase
        }
        
        # Get repositories
        repos = await self.get_github_repos(account_name, scan_type)
        findings["stats"]["total_repos"] = len(repos)
        
        if not repos:
            return findings
        
        # Create temporary directory for cloning
        temp_dir = tempfile.mkdtemp(prefix="github_scan_")
        print(f"Created temp directory: {temp_dir}")
        
        try:
            all_bucket_urls = set()
            
            for i, repo in enumerate(repos):
                print(f"\n[{i+1}/{len(repos)}] Processing {repo['name']}")
                
                # Clone repository (shallow)
                repo_path = await self.clone_repository(repo["clone_url"], temp_dir)
                
                if repo_path:
                    # Scan repository
                    secrets, bucket_urls = await self.scan_repository(repo_path)
                    
                    # Add repo info to findings
                    for secret in secrets:
                        secret["repo"] = repo["name"]
                        secret["repo_url"] = f"https://github.com/{repo['full_name']}"
                        secret["repo_type"] = "private" if repo["private"] else "public"
                        secret["repo_archived"] = repo["archived"]
                    
                    findings["secrets"].extend(secrets)
                    
                    # Add bucket URLs with type
                    for bucket_url, bucket_type in bucket_urls:
                        all_bucket_urls.add((bucket_url, bucket_type))
                    
                    # Update stats
                    findings["stats"]["secrets_found"] += len(secrets)
                
                findings["stats"]["scanned_repos"] = i + 1
                
                # Clean up cloned repo immediately to save space
                if repo_path and os.path.exists(repo_path):
                    shutil.rmtree(repo_path, ignore_errors=True)
            
            # Store unique bucket URLs for second phase
            unique_bucket_urls = []
            for bucket_url, bucket_type in all_bucket_urls:
                unique_bucket_urls.append({
                    "url": bucket_url,
                    "type": bucket_type,
                    "status": "pending"
                })
            
            findings["bucket_urls"] = unique_bucket_urls
            findings["stats"]["bucket_urls_found"] = len(unique_bucket_urls)
            
        except Exception as e:
            print(f"Error during secret scan: {e}")
            import traceback
            traceback.print_exc()
        
        finally:
            # Clean up temporary directory
            if os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    print(f"Cleaned up temp directory: {temp_dir}")
                except:
                    pass
        
        return findings
    
    async def check_bucket_vulnerability(self, bucket_url: str, bucket_type: str) -> Dict:
        """Check if a cloud bucket is vulnerable to takeover (second phase)"""
        vulnerable = False
        status = "unknown"
        response_code = 0
        response_time = 0
        error = None
        
        # Prepare URLs to check based on bucket type
        urls_to_try = []
        
        if bucket_type == "aws_s3_url" and bucket_url.startswith("s3://"):
            bucket_name = bucket_url.replace("s3://", "").split("/")[0]
            urls_to_try.extend([
                f"http://{bucket_name}.s3.amazonaws.com",
                f"https://{bucket_name}.s3.amazonaws.com",
                f"http://{bucket_name}.s3-website-us-east-1.amazonaws.com",
                f"https://{bucket_name}.s3-website-us-east-1.amazonaws.com"
            ])
        elif "s3" in bucket_type and "." in bucket_url:
            # Already a full URL
            urls_to_try.extend([
                f"http://{bucket_url}",
                f"https://{bucket_url}"
            ])
        elif "azure" in bucket_type:
            urls_to_try.extend([
                f"http://{bucket_url}",
                f"https://{bucket_url}"
            ])
        elif "google" in bucket_type or "gcp" in bucket_type:
            urls_to_try.extend([
                f"http://{bucket_url}",
                f"https://{bucket_url}"
            ])
        else:
            # Try generic approach
            urls_to_try.extend([
                f"http://{bucket_url}",
                f"https://{bucket_url}"
            ])
        
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            for url in urls_to_try:
                try:
                    start_time = datetime.now()
                    response = await client.get(url)
                    response_time = (datetime.now() - start_time).total_seconds()
                    
                    response_code = response.status_code
                    content = response.text.lower()
                    
                    # Check for takeover indicators
                    takeover_indicators = [
                        "nosuchbucket",
                        "no such bucket",
                        "specified bucket does not exist",
                        "bucketnotfound",
                        "bucket does not exist",
                        "404 not found",
                        "the specified bucket does not exist",
                        "no such website configuration",
                        "error 404",
                        "notfound"
                    ]
                    
                    if response.status_code == 404 or any(indicator in content for indicator in takeover_indicators):
                        vulnerable = True
                        status = "🚨 VULNERABLE - Possible takeover"
                        break
                    elif response.status_code == 403 or "access denied" in content or "accessdenied" in content:
                        status = "🔒 Protected (Access Denied)"
                        break
                    elif response.status_code == 200:
                        # Check if it's a listing page or actual content
                        if any(tag in content for tag in ["<listbucketresult", "<bucket", "aws", "amazon", "s3"]):
                            status = "⚠️ Public - Bucket listing enabled"
                        elif "index.html" in content or "<html" in content:
                            status = "🌐 Public - Hosting website"
                        else:
                            status = "📄 Public - Hosting content"
                        break
                    elif response.status_code == 400:
                        status = "❌ Bad request - May be misconfigured"
                        break
                    elif response.status_code == 500:
                        status = "💥 Server error"
                        break
                    else:
                        status = f"Status {response.status_code}"
                        
                except httpx.ConnectError:
                    status = "🔌 Connection failed"
                except httpx.TimeoutException:
                    status = "⏰ Timeout"
                except httpx.RequestError as e:
                    status = f"⚠️ Request error"
                    error = str(e)
                except Exception as e:
                    status = f"❌ Error"
                    error = str(e)
        
        result = {
            "url": bucket_url,
            "type": bucket_type,
            "vulnerable": vulnerable,
            "status": status,
            "response_code": response_code,
            "response_time": response_time,
            "checked_at": datetime.now().isoformat()
        }
        
        if error:
            result["error"] = error
        
        return result