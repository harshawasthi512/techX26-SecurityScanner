import aiohttp
import asyncio
import re
from typing import List, Dict, Set, Tuple, Optional
import urllib.parse
from datetime import datetime
import logging
from dataclasses import dataclass
from collections import defaultdict
import json
import random

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ScanResult:
    """Structure to store scan results without duplicates"""
    sensitive_tokens: List[Dict]
    sensitive_endpoints: List[Dict]
    idor_params: List[Dict]
    open_redirect_params: List[Dict]
    stats: Dict
    all_urls: List[str]

class WaySecretsScanner:
    def __init__(self):
        # Wayback Machine API endpoint (using the simpler version that works)
        self.wayback_api = "http://web.archive.org/cdx/search/cdx"
        
        # Common endpoints to test if Wayback has no data
        self.common_endpoints = [
            # Admin endpoints
            '/admin', '/admin/', '/admin/index.php', '/admin/login', '/admin/dashboard',
            '/administrator', '/administrator/', '/wp-admin', '/wp-login.php',
            '/cp', '/controlpanel', '/manager', '/backend', '/cpanel',
            
            # Login endpoints
            '/login', '/login/', '/signin', '/signin/', '/auth', '/authenticate',
            '/oauth', '/oauth2', '/sso', '/account/login', '/user/login',
            
            # API endpoints
            '/api', '/api/', '/api/v1', '/api/v2', '/api/v3', '/graphql',
            '/rest', '/rest/', '/soap', '/webservice', '/ws',
            
            # Configuration files
            '/.env', '/config.php', '/configuration.php', '/settings.php',
            '/config.json', '/config.yml', '/config.yaml', '/config.ini',
            '/application.properties', '/web.config',
            
            # Backup files
            '/backup', '/backup/', '/backup.zip', '/backup.tar', '/backup.sql',
            '/dump.sql', '/database.sql', '/backup/backup.sql',
            
            # Sensitive directories
            '/private', '/secret', '/hidden', '/internal', '/secure',
            '/test', '/dev', '/development', '/staging', '/debug',
            
            # User endpoints
            '/profile', '/user/profile', '/account', '/account/settings',
            '/dashboard', '/myaccount', '/users', '/members',
            
            # Common vulnerable endpoints
            '/phpinfo.php', '/info.php', '/test.php', '/debug.php',
            '/console', '/actuator', '/health', '/metrics',
            
            # File upload endpoints
            '/upload', '/upload/', '/fileupload', '/attachment',
            
            # Search endpoints
            '/search', '/find', '/query',
        ]
        
        # Subdomains to test
        self.common_subdomains = [
            'www', 'api', 'test', 'dev', 'staging', 'admin', 'secure',
            'mail', 'webmail', 'portal', 'dashboard', 'app', 'apps'
        ]
        
        # Ignore patterns for documentation/blog URLs
        self.ignore_patterns = [
            r"/docs?/",
            r"/documentation/",
            r"/help/",
            r"/support/",
            r"/blog/",
            r"/articles?/",
            r"/tutorials?/",
            r"/guides?/",
            r"/api/v\d+/docs?",
            r"/swagger",
            r"/redoc",
            r"/readme",
            r"/changelog",
            r"/release-notes",
            r"\.pdf$",
            r"\.docx?$",
            r"\.txt$",
            r"index\.(html|php|asp|aspx)$"
        ]
        
        # Compile ignore patterns
        self.ignore_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.ignore_patterns]
        
        # Enhanced sensitive token patterns
        self.token_patterns = {
            'aws_access_key': r'\bAKIA[0-9A-Z]{16}\b',
            'aws_secret_key': r'\b[Aa][Ww][Ss].{0,20}[''\"][A-Za-z0-9+/]{40}[''\"]',
            'api_key': r'\b(?:api[_-]?key|apikey)[\s=:]+[''\"]([A-Za-z0-9_\-]{32,})[''\"]',
            'bearer_token': r'\bBearer\s+[A-Za-z0-9\-_=]{100,}\b',
            'jwt_token': r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b',
            'github_token': r'\bgh[pousr]_[A-Za-z0-9_]{36}\b',
            'slack_token': r'\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b',
            'firebase_key': r'\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b',
            'stripe_key': r'\b(sk_live|rk_live)_[0-9a-zA-Z]{24}\b',
            'database_url': r'\b(mysql|postgres|mongodb|redis)://[^\s\'\"<>]+',
            'private_key': r'-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----',
            'ssh_key': r'ssh-(?:rsa|dss|ed25519) AAAA[0-9A-Za-z+/]+[=]{0,3}',
            'google_api': r'\bAIza[0-9A-Za-z\-_]{35}\b',
            'facebook_token': r'\bEAACEdEose0cBA[0-9A-Za-z]+\b',
            'twitter_token': r'\b[0-9]{15,25}-[0-9a-zA-Z]{40}\b',
            'password_in_url': r'(?i)(?:password|passwd|pwd)[=:][^&\s]+',
            'secret_in_url': r'(?i)(?:secret|token|key)[=:][^&\s]{10,}',
        }
        
        # Sensitive endpoint patterns
        self.endpoint_patterns = [
            (r'/(admin|administrator|cp|controlpanel|manager|backend|cpanel)', 'Admin Panel'),
            (r'/(login|signin|auth|authenticate|oauth|sso)', 'Authentication'),
            (r'/api/.*(key|token|secret|password|auth)', 'API Secrets'),
            (r'/(config|configuration|settings|\.env|\.config)', 'Configuration'),
            (r'/(backup|dump|sql|database\.|\.bak|\.old)', 'Backup Files'),
            (r'/(phpmyadmin|adminer|myadmin|dbadmin)', 'Database Admin'),
            (r'/(test|debug|dev|staging|uat)', 'Development/Test'),
            (r'/wp-(admin|login|config)', 'WordPress'),
            (r'/(\.git|\.svn|\.hg|CVS)/', 'Version Control'),
            (r'/(bash_history|\.history|\.bash_history)', 'Shell History'),
            (r'/(upload|fileupload|attachment)', 'File Upload'),
            (r'/(console|shell|terminal|cmd)', 'Command Interface'),
            (r'/(phpinfo|info\.php|test\.php)', 'PHP Info'),
            (r'/(actuator|health|metrics|prometheus)', 'Monitoring'),
            (r'/(\.aws|\.ssh|\.docker)/', 'Cloud Config'),
        ]
        
        # IDOR parameter patterns
        self.idor_params = [
            'id', 'user', 'account', 'profile', 'uid', 'userid', 'accountid',
            'customer', 'client', 'order', 'invoice', 'document', 'file',
            'patient', 'student', 'employee', 'member', 'contact',
            'product', 'item', 'asset', 'resource', 'record'
        ]
        
        # Open redirect parameter patterns
        self.redirect_params = [
            'redirect', 'url', 'next', 'return', 'returnTo', 'goto',
            'forward', 'destination', 'target', 'r', 'u', 'link',
            'continue', 'callback', 'success', 'error', 'logout'
        ]
        
        # Performance settings
        self.max_urls = 2000  # Increased limit
        self.max_concurrent = 30
        self.timeout = 30
        self.request_delay = 0.1
        
        # Cache for already seen patterns to avoid duplicates
        self.seen_patterns = set()
        
    def should_ignore_url(self, url: str) -> bool:
        """Check if URL should be ignored"""
        url_lower = url.lower()
        
        # Check ignore patterns
        for pattern in self.ignore_regex:
            if pattern.search(url):
                return True
        
        return False
    
    async def test_wayback_api(self, domain: str):
        """Test the Wayback API endpoint to see what's returned"""
        logger.info(f"🔍 Testing Wayback API for {domain}")
        
        test_params = [
            {'url': f'{domain}/*', 'output': 'json', 'fl': 'original', 'collapse': 'urlkey'},
            {'url': f'*.{domain}/*', 'output': 'json', 'fl': 'original', 'collapse': 'urlkey'},
            {'url': f'www.{domain}/*', 'output': 'json', 'fl': 'original', 'collapse': 'urlkey'},
        ]
        
        for params in test_params:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(self.wayback_api, params=params, ssl=False) as response:
                        logger.info(f"Test request: {params}")
                        logger.info(f"Status: {response.status}")
                        
                        if response.status == 200:
                            content = await response.text()
                            logger.info(f"Response length: {len(content)} chars")
                            
                            # Try to parse as JSON
                            try:
                                data = json.loads(content)
                                if isinstance(data, list):
                                    logger.info(f"JSON rows: {len(data)}")
                                    if len(data) > 1:
                                        logger.info(f"First URL: {data[1][0] if len(data[1]) > 0 else 'N/A'}")
                                else:
                                    logger.info(f"JSON type: {type(data)}")
                            except json.JSONDecodeError:
                                logger.info("Response is not JSON, trying as text...")
                                lines = content.strip().split('\n')
                                logger.info(f"Text lines: {len(lines)}")
                                if lines and len(lines) > 1:
                                    logger.info(f"First line: {lines[1][:100]}...")
                        else:
                            logger.info(f"Response text: {await response.text()[:200]}")
                            
            except Exception as e:
                logger.error(f"Test error: {e}")
            
            await asyncio.sleep(1)
    
    async def fetch_wayback_urls_simple(self, domain: str) -> List[str]:
        """Fetch URLs from Wayback Machine using the simple endpoint that works"""
        urls = []
        
        try:
            # Try multiple domain patterns
            domain_patterns = [
                domain,
                f"*.{domain}",
                f"www.{domain}",
                f"*.{domain}/*"
            ]
            
            for domain_pattern in domain_patterns:
                params = {
                    'url': f"{domain_pattern}/*",
                    'output': 'json',
                    'fl': 'original',
                    'collapse': 'urlkey'
                }
                
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'application/json',
                }
                
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    headers=headers
                ) as session:
                    async with session.get(self.wayback_api, params=params, ssl=False) as response:
                        if response.status == 200:
                            try:
                                data = await response.json()
                                if data and len(data) > 1:
                                    for row in data[1:]:  # Skip header
                                        if row and len(row) > 0:
                                            url = row[0]
                                            if url and not self.should_ignore_url(url):
                                                urls.append(url)
                                    logger.info(f"Found {len(urls)} URLs for pattern {domain_pattern}")
                                    
                                    # If we got URLs, we can break
                                    if urls:
                                        break
                            except Exception as e:
                                logger.warning(f"JSON parse error: {e}")
                                # Try to parse as text
                                text = await response.text()
                                lines = text.strip().split('\n')
                                for line in lines:
                                    if line and not line.startswith('original'):
                                        url = line.strip()
                                        if url and not self.should_ignore_url(url):
                                            urls.append(url)
                                logger.info(f"Found {len(urls)} URLs (text format) for pattern {domain_pattern}")
                                if urls:
                                    break
                
                # Small delay between requests
                await asyncio.sleep(0.5)
        
        except Exception as e:
            logger.error(f"Error fetching Wayback URLs: {e}")
        
        # Remove duplicates
        seen = set()
        unique_urls = []
        for url in urls:
            if url not in seen:
                seen.add(url)
                unique_urls.append(url)
        
        return unique_urls[:self.max_urls]
    
    async def fetch_wayback_urls_with_pagination(self, domain: str) -> List[str]:
        """Fetch URLs with pagination to get more results"""
        urls = []
        offset = 0
        limit = 5000  # Max per request
        
        try:
            while offset < 20000:  # Max total URLs to fetch
                params = {
                    'url': f"{domain}/*",
                    'output': 'json',
                    'fl': 'original',
                    'collapse': 'urlkey',
                    'limit': str(limit),
                    'offset': str(offset)
                }
                
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'application/json',
                }
                
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    headers=headers
                ) as session:
                    async with session.get(self.wayback_api, params=params, ssl=False) as response:
                        if response.status == 200:
                            try:
                                data = await response.json()
                                if not data or len(data) <= 1:
                                    break  # No more data
                                
                                batch_urls = []
                                for row in data[1:]:  # Skip header
                                    if row and len(row) > 0:
                                        url = row[0]
                                        if url and not self.should_ignore_url(url):
                                            batch_urls.append(url)
                                
                                if not batch_urls:
                                    break  # No more URLs
                                
                                urls.extend(batch_urls)
                                logger.info(f"Batch {offset//limit + 1}: Found {len(batch_urls)} URLs (Total: {len(urls)})")
                                
                                if len(batch_urls) < limit:
                                    break  # Last batch
                                
                                offset += limit
                                await asyncio.sleep(1)  # Delay between batches
                                
                            except Exception as e:
                                logger.warning(f"Error processing batch: {e}")
                                break
                        else:
                            logger.warning(f"HTTP {response.status} for batch")
                            break
        
        except Exception as e:
            logger.error(f"Error in paginated fetch: {e}")
        
        # Remove duplicates
        seen = set()
        unique_urls = []
        for url in urls:
            if url not in seen:
                seen.add(url)
                unique_urls.append(url)
        
        return unique_urls[:self.max_urls]
    
    def generate_test_urls(self, domain: str) -> List[str]:
        """Generate comprehensive test URLs"""
        urls = []
        protocols = ['http://', 'https://']
        subdomains = ['', 'www']  # Just base and www for simplicity
        
        for protocol in protocols:
            for subdomain in subdomains:
                # Build base URL
                if subdomain:
                    base_url = f"{protocol}{subdomain}.{domain}"
                else:
                    base_url = f"{protocol}{domain}"
                
                # Add common endpoints
                for endpoint in self.common_endpoints[:50]:  # Limit to 50 endpoints
                    urls.append(f"{base_url}{endpoint}")
                
                # Add parameter variations
                param_urls = [
                    f"{base_url}/user?id=123",
                    f"{base_url}/profile?user=456",
                    f"{base_url}/account?id=789",
                    f"{base_url}/api?key=test",
                    f"{base_url}/login?redirect=http://evil.com",
                    f"{base_url}/auth?token=abc123",
                    f"{base_url}/search?q=test",
                    f"{base_url}/download?file=../../etc/passwd",
                    f"{base_url}/api/v1/users?api_key=test123",
                ]
                urls.extend(param_urls)
        
        # Remove duplicates
        unique_urls = list(set(urls))
        
        return unique_urls[:200]  # Limit to 200 test URLs
    
    def detect_sensitive_tokens(self, url: str) -> List[Dict]:
        """Detect sensitive tokens in URL"""
        findings = []
        
        # Decode URL to catch encoded tokens
        decoded_url = urllib.parse.unquote(url)
        
        for token_type, pattern in self.token_patterns.items():
            try:
                # Search in both original and decoded URL
                for search_text in [url, decoded_url]:
                    matches = re.finditer(pattern, search_text, re.IGNORECASE)
                    for match in matches:
                        token = match.group()
                        
                        # Skip obvious false positives
                        if len(token) < 10:
                            continue
                        
                        # Check for common false positive patterns
                        if token_type == 'api_key' and 'example' in token.lower():
                            continue
                        if token_type == 'database_url' and 'localhost' in token.lower():
                            continue
                        
                        # Create a unique identifier
                        token_hash = hash(token) % 1000000
                        finding_id = f"{token_type}:{token_hash}"
                        
                        if finding_id not in self.seen_patterns:
                            self.seen_patterns.add(finding_id)
                            
                            # Truncate for display
                            display_token = token
                            if len(token) > 60:
                                display_token = token[:30] + "..." + token[-20:]
                            
                            findings.append({
                                'type': token_type,
                                'token': display_token,
                                'url': url[:150] + "..." if len(url) > 150 else url,
                                'full_match': token[:100] if len(token) > 100 else token,
                                'confidence': 'high' if len(token) > 20 else 'medium'
                            })
            except Exception as e:
                continue
        
        return findings
    
    def detect_sensitive_endpoints(self, url: str) -> List[Dict]:
        """Detect sensitive endpoints in URL"""
        findings = []
        
        try:
            parsed = urllib.parse.urlparse(url)
            path = parsed.path
            
            # Skip if path is too short or just /
            if len(path) <= 1:
                return findings
            
            for pattern, label in self.endpoint_patterns:
                if re.search(pattern, path, re.IGNORECASE):
                    # Check for false positives
                    if label == 'Configuration' and not re.search(r'\.(env|config|cfg|ini|yml|yaml|json|properties)$', path, re.IGNORECASE):
                        continue
                    
                    finding_id = f"{label}:{hash(path) % 1000000}"
                    
                    if finding_id not in self.seen_patterns:
                        self.seen_patterns.add(finding_id)
                        
                        # Extract interesting parts
                        query = parsed.query
                        fragment = parsed.fragment
                        
                        findings.append({
                            'type': 'sensitive_endpoint',
                            'label': label,
                            'url': url[:150] + "..." if len(url) > 150 else url,
                            'path': path,
                            'query': query if query else None,
                            'fragment': fragment if fragment else None,
                            'confidence': 'high'
                        })
                        break
        except Exception:
            pass
        
        return findings
    
    def detect_idor_params(self, url: str) -> List[Dict]:
        """Detect potential IDOR parameters in URL"""
        findings = []
        
        try:
            parsed = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed.query)
            
            for param in self.idor_params:
                if param in query_params:
                    values = query_params[param]
                    for value in values:
                        # Skip empty values
                        if not value or len(value.strip()) == 0:
                            continue
                        
                        # Check for numeric IDs
                        if value.isdigit() and 1 <= len(value) <= 10:
                            finding_id = f"idor:{param}:{value}"
                            
                            if finding_id not in self.seen_patterns:
                                self.seen_patterns.add(finding_id)
                                findings.append({
                                    'type': 'idor_param',
                                    'param': param,
                                    'value': value,
                                    'url': url[:150] + "..." if len(url) > 150 else url,
                                    'vulnerability': 'Potential IDOR - Numeric ID parameter',
                                    'confidence': 'medium'
                                })
                        
                        # Check for UUIDs
                        elif re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', value.lower()):
                            finding_id = f"idor:{param}:uuid:{value[:8]}"
                            
                            if finding_id not in self.seen_patterns:
                                self.seen_patterns.add(finding_id)
                                findings.append({
                                    'type': 'idor_param',
                                    'param': param,
                                    'value': value,
                                    'url': url[:150] + "..." if len(url) > 150 else url,
                                    'vulnerability': 'Potential IDOR - UUID parameter',
                                    'confidence': 'medium'
                                })
                        
                        # Check for other ID-like patterns
                        elif re.match(r'^[A-Z0-9]{6,20}$', value):
                            finding_id = f"idor:{param}:alphanum:{value}"
                            
                            if finding_id not in self.seen_patterns:
                                self.seen_patterns.add(finding_id)
                                findings.append({
                                    'type': 'idor_param',
                                    'param': param,
                                    'value': value,
                                    'url': url[:150] + "..." if len(url) > 150 else url,
                                    'vulnerability': 'Potential IDOR - Alphanumeric ID',
                                    'confidence': 'low'
                                })
        except Exception:
            pass
        
        return findings
    
    def detect_open_redirect_params(self, url: str) -> List[Dict]:
        """Detect potential open redirect parameters in URL"""
        findings = []
        
        try:
            parsed = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed.query)
            
            for param in self.redirect_params:
                if param in query_params:
                    values = query_params[param]
                    for value in values:
                        # Skip empty values
                        if not value or len(value.strip()) == 0:
                            continue
                        
                        # Check for full URLs
                        if re.match(r'^(http|https|ftp)://', value, re.IGNORECASE):
                            # Check if it's external
                            parsed_value = urllib.parse.urlparse(value.lower())
                            if parsed_value.netloc and not parsed.netloc.endswith(parsed_value.netloc):
                                finding_id = f"redirect:{param}:{hash(value) % 1000000}"
                                
                                if finding_id not in self.seen_patterns:
                                    self.seen_patterns.add(finding_id)
                                    findings.append({
                                        'type': 'open_redirect',
                                        'param': param,
                                        'value': value[:100] + "..." if len(value) > 100 else value,
                                        'url': url[:150] + "..." if len(url) > 150 else url,
                                        'vulnerability': 'Potential Open Redirect - External URL',
                                        'confidence': 'high'
                                    })
                        
                        # Check for protocol-less redirects
                        elif '://' not in value and len(value) > 3:
                            # Check if it looks like a path that could be manipulated
                            if not value.startswith(('/', '#', '?')) and '/' in value:
                                finding_id = f"redirect:{param}:path:{hash(value) % 1000000}"
                                
                                if finding_id not in self.seen_patterns:
                                    self.seen_patterns.add(finding_id)
                                    findings.append({
                                        'type': 'open_redirect',
                                        'param': param,
                                        'value': value,
                                        'url': url[:150] + "..." if len(url) > 150 else url,
                                        'vulnerability': 'Potential Open Redirect - Dynamic path',
                                        'confidence': 'medium'
                                    })
        except Exception:
            pass
        
        return findings
    
    async def scan_url(self, url: str) -> Dict:
        """Scan a single URL for all findings"""
        findings = {
            'tokens': [],
            'endpoints': [],
            'idor': [],
            'redirect': []
        }
        
        try:
            # Skip obviously uninteresting URLs
            if self.should_ignore_url(url):
                return findings
            
            # Check for sensitive tokens
            findings['tokens'] = self.detect_sensitive_tokens(url)
            
            # Check for sensitive endpoints
            findings['endpoints'] = self.detect_sensitive_endpoints(url)
            
            # Check for IDOR parameters
            findings['idor'] = self.detect_idor_params(url)
            
            # Check for open redirect parameters
            findings['redirect'] = self.detect_open_redirect_params(url)
            
        except Exception as e:
            pass  # Silently skip errors for individual URLs
        
        return findings
    
    async def scan_domain(self, domain: str) -> ScanResult:
        """Main scanning function for a domain"""
        logger.info(f"🚀 Starting WaySecrets scan for: {domain}")
        start_time = datetime.now()
        
        # Reset cache
        self.seen_patterns.clear()
        
        # Phase 1: Fetch from Wayback Machine using simple method
        logger.info(f"🌐 Fetching URLs from Wayback Machine...")
        
        # Try simple method first
        wayback_urls = await self.fetch_wayback_urls_simple(domain)
        
        # If we got few URLs, try paginated method
        if len(wayback_urls) < 100:
            logger.info(f"⚠️  Only {len(wayback_urls)} URLs from simple fetch, trying paginated...")
            paginated_urls = await self.fetch_wayback_urls_with_pagination(domain)
            # Merge URLs
            all_wayback_urls = list(set(wayback_urls + paginated_urls))
            wayback_urls = all_wayback_urls[:self.max_urls]
        
        # Phase 2: Generate test URLs if needed
        test_urls = []
        if len(wayback_urls) < 50:
            logger.info(f"⚠️  Only {len(wayback_urls)} URLs from Wayback, generating test URLs...")
            test_urls = self.generate_test_urls(domain)
        
        # Combine URLs
        all_urls = wayback_urls + test_urls
        total_urls = len(all_urls)
        
        logger.info(f"📊 Total URLs to scan: {total_urls} ({len(wayback_urls)} from Wayback, {len(test_urls)} generated)")
        
        # Initialize results
        sensitive_tokens = []
        sensitive_endpoints = []
        idor_params = []
        open_redirect_params = []
        
        # Scan URLs efficiently
        if all_urls:
            # Create tasks for scanning
            tasks = []
            for url in all_urls[:1000]:  # Limit to 1000 URLs for performance
                task = asyncio.create_task(self.scan_url(url))
                tasks.append(task)
            
            # Process in smaller batches to show progress
            total_tasks = len(tasks)
            completed = 0
            batch_size = 50
            
            for i in range(0, total_tasks, batch_size):
                batch = tasks[i:i + batch_size]
                batch_results = await asyncio.gather(*batch, return_exceptions=True)
                
                for result in batch_results:
                    if isinstance(result, Exception):
                        continue
                    
                    # Collect findings
                    sensitive_tokens.extend(result['tokens'])
                    sensitive_endpoints.extend(result['endpoints'])
                    idor_params.extend(result['idor'])
                    open_redirect_params.extend(result['redirect'])
                
                completed += len(batch)
                progress = min(100, int(completed / total_tasks * 100))
                
                if i % 200 == 0:  # Log every 200 URLs
                    logger.info(f"📈 Scan progress: {progress}% ({completed}/{total_tasks} URLs)")
        
        # Calculate duration
        duration = (datetime.now() - start_time).total_seconds()
        
        # Prepare statistics
        stats = {
            'domain': domain,
            'total_urls_fetched': total_urls,
            'urls_scanned': min(total_urls, 1000),
            'sensitive_tokens_found': len(sensitive_tokens),
            'sensitive_endpoints_found': len(sensitive_endpoints),
            'idor_params_found': len(idor_params),
            'open_redirect_params_found': len(open_redirect_params),
            'scan_duration': round(duration, 2),
            'wayback_urls': len(wayback_urls),
            'generated_urls': len(test_urls),
            'timestamp': datetime.now().isoformat()
        }
        
        # Prepare sample URLs
        unique_sample_urls = []
        seen_urls = set()
        for url in all_urls[:100]:
            if url not in seen_urls:
                seen_urls.add(url)
                unique_sample_urls.append(url)
        
        # Create result
        result = ScanResult(
            sensitive_tokens=sensitive_tokens[:200],
            sensitive_endpoints=sensitive_endpoints[:200],
            idor_params=idor_params[:200],
            open_redirect_params=open_redirect_params[:200],
            stats=stats,
            all_urls=unique_sample_urls
        )
        
        logger.info(f"✅ Scan completed in {duration:.2f}s")
        logger.info(f"📋 Results: {len(sensitive_tokens)} tokens, {len(sensitive_endpoints)} endpoints, "
                   f"{len(idor_params)} IDOR params, {len(open_redirect_params)} redirect params")
        
        return result