import streamlit as st
import pandas as pd
import json
import time
import requests
import re
from datetime import datetime
from openai import OpenAI
from io import BytesIO
import os
from dotenv import load_dotenv
import shlex
from urllib.parse import urlparse, parse_qs
import zipfile

# Load environment variables
load_dotenv()

# Page configuration
st.set_page_config(
    page_title="GPT API Security Tester",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better UI
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .success-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #d4edda;
        border: 1px solid #c3e6cb;
        color: #155724;
        margin: 1rem 0;
    }
    .error-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #f8d7da;
        border: 1px solid #f5c6cb;
        color: #721c24;
        margin: 1rem 0;
    }
    .info-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #d1ecf1;
        border: 1px solid #bee5eb;
        color: #0c5460;
        margin: 1rem 0;
    }
    .code-input {
        font-family: 'Courier New', monospace;
        font-size: 14px;
    }
    .upload-section {
        border: 2px dashed #ccc;
        border-radius: 10px;
        padding: 20px;
        text-align: center;
        margin: 10px 0;
    }
</style>
""", unsafe_allow_html=True)

def initialize_openai_client(api_key):
    """Initialize OpenAI client with provided API key - IMPROVED VERSION"""
    try:
        if not api_key or not api_key.strip():
            return None, "No API key provided"
        
        # Remove any whitespace and validate format
        cleaned_key = api_key.strip()
        
        # Basic validation - OpenAI keys start with 'sk-'
        if not cleaned_key.startswith('sk-'):
            return None, "Invalid API key format. OpenAI keys should start with 'sk-'"
        
        # Initialize client
        client = OpenAI(api_key=cleaned_key)
        
        # CRITICAL FIX: Test with a minimal request
        try:
            test_response = client.chat.completions.create(
                model="gpt-3.5-turbo",  # Use cheaper model for testing
                messages=[{"role": "user", "content": "test"}],
                max_tokens=1,
                temperature=0
            )
            return client, "success"
        except Exception as test_error:
            # If test fails, try with the original models.list() approach
            try:
                client.models.list()
                return client, "success"
            except Exception as models_error:
                return None, f"API key validation failed: {str(test_error)}"
        
    except Exception as e:
        return None, f"Client initialization error: {str(e)}"

def read_uploaded_files(uploaded_files):
    """Read content from uploaded files"""
    all_content = ""
    file_info = []
    
    for uploaded_file in uploaded_files:
        try:
            if uploaded_file.type == "text/plain" or uploaded_file.name.endswith(('.py', '.js', '.ts', '.java', '.php', '.rb', '.go', '.rs')):
                content = str(uploaded_file.read(), "utf-8")
                all_content += f"\n\n# === File: {uploaded_file.name} ===\n"
                all_content += content
                file_info.append({"name": uploaded_file.name, "size": len(content), "type": uploaded_file.type})
            
            elif uploaded_file.name.endswith('.zip'):
                # Handle ZIP files
                with zipfile.ZipFile(uploaded_file, 'r') as zip_file:
                    for file_name in zip_file.namelist():
                        if file_name.endswith(('.py', '.js', '.ts', '.java', '.php', '.rb', '.go', '.rs', '.txt')):
                            try:
                                with zip_file.open(file_name) as file:
                                    content = file.read().decode('utf-8')
                                    all_content += f"\n\n# === File: {file_name} (from {uploaded_file.name}) ===\n"
                                    all_content += content
                                    file_info.append({"name": file_name, "size": len(content), "type": "from_zip"})
                            except Exception as e:
                                st.warning(f"Could not read {file_name} from zip: {e}")
            
        except Exception as e:
            st.error(f"Error reading {uploaded_file.name}: {e}")
    
    return all_content, file_info

def parse_curl_command(curl_command):
    """Parse curl command to extract URL, method, headers, and data"""
    try:
        # Remove curl from the beginning if present
        curl_command = curl_command.strip()
        if curl_command.startswith('curl'):
            curl_command = curl_command[4:].strip()
        
        # Use shlex to properly parse the command
        parts = shlex.split(curl_command)
        
        url = None
        method = 'GET'
        headers = {}
        data = None
        
        i = 0
        while i < len(parts):
            part = parts[i]
            
            if part.startswith('http'):
                url = part
            elif part in ['-X', '--request']:
                if i + 1 < len(parts):
                    method = parts[i + 1].upper()
                    i += 1
            elif part in ['-H', '--header']:
                if i + 1 < len(parts):
                    header_str = parts[i + 1]
                    if ':' in header_str:
                        key, value = header_str.split(':', 1)
                        headers[key.strip()] = value.strip()
                    i += 1
            elif part in ['-d', '--data', '--data-raw']:
                if i + 1 < len(parts):
                    data_str = parts[i + 1]
                    try:
                        data = json.loads(data_str)
                    except json.JSONDecodeError:
                        # If not JSON, treat as form data or plain text
                        data = data_str
                    i += 1
            
            i += 1
        
        if not url:
            return None, "No URL found in curl command"
        
        return {
            'url': url,
            'method': method,
            'headers': headers,
            'data': data
        }, None
        
    except Exception as e:
        return None, f"Error parsing curl command: {str(e)}"

def analyze_code_context(code, context_info=""):
    """Analyze code and context to extract detailed API information for intelligent test generation"""
    analysis = {
        'endpoints': [],
        'authentication_methods': [],
        'validation_patterns': [],
        'business_logic': [],
        'security_controls': [],
        'data_flows': [],
        'error_handling': [],
        'dependencies': [],
        'database_operations': [],
        'file_operations': [],
        'external_apis': [],
        'rate_limiting': [],
        'input_sources': [],
        'output_patterns': []
    }
    
    # Combine code and context for comprehensive analysis
    full_content = f"{code}\n\n# Context Information:\n{context_info}"
    
    # Authentication Analysis
    auth_patterns = [
        (r'@require_auth|@login_required|@authenticated', 'decorator_auth'),
        (r'Authorization|Bearer|JWT|token', 'token_auth'),
        (r'session\.|request\.session', 'session_auth'),
        (r'BasicAuth|basic_auth', 'basic_auth'),
        (r'OAuth|oauth', 'oauth'),
        (r'API[_-]?KEY|api[_-]?key', 'api_key'),
        (r'CSRF|csrf', 'csrf_protection'),
        (r'verify_password|check_password|authenticate', 'password_auth')
    ]
    
    for pattern, auth_type in auth_patterns:
        if re.search(pattern, full_content, re.IGNORECASE):
            analysis['authentication_methods'].append(auth_type)
    
    # Input Validation Patterns
    validation_patterns = [
        (r'validate|validator|Schema|schema', 'schema_validation'),
        (r'required|optional|nullable', 'field_requirements'),
        (r'min_length|max_length|length', 'length_validation'),
        (r'email|Email|EMAIL_REGEX', 'email_validation'),
        (r'int|integer|float|number', 'type_validation'),
        (r'sanitize|escape|clean', 'input_sanitization'),
        (r'regex|pattern|match', 'pattern_validation'),
        (r'range|between|min|max', 'range_validation')
    ]
    
    for pattern, validation_type in validation_patterns:
        if re.search(pattern, full_content, re.IGNORECASE):
            analysis['validation_patterns'].append(validation_type)
    
    # Business Logic Detection
    business_logic_patterns = [
        (r'if.*role|permission|access', 'role_based_logic'),
        (r'balance|payment|transaction|charge', 'financial_logic'),
        (r'user_id|owner|belongs_to', 'ownership_logic'),
        (r'status.*==|state.*==', 'state_dependent_logic'),
        (r'limit|quota|throttle', 'limit_logic'),
        (r'workflow|process|step', 'workflow_logic'),
        (r'calculate|compute|process', 'calculation_logic'),
        (r'notification|email|sms|alert', 'notification_logic')
    ]
    
    for pattern, logic_type in business_logic_patterns:
        if re.search(pattern, full_content, re.IGNORECASE):
            analysis['business_logic'].append(logic_type)
    
    # Security Controls
    security_patterns = [
        (r'hash|bcrypt|scrypt|pbkdf2', 'password_hashing'),
        (r'encrypt|decrypt|cipher', 'encryption'),
        (r'rate_limit|throttle|cooldown', 'rate_limiting'),
        (r'CORS|cors|cross.origin', 'cors_controls'),
        (r'Content-Security-Policy|CSP', 'csp_headers'),
        (r'XSS|xss|cross.site', 'xss_protection'),
        (r'SQL.*injection|parameterized|prepared', 'sql_injection_protection'),
        (r'whitelist|blacklist|allow|deny', 'input_filtering')
    ]
    
    for pattern, security_type in security_patterns:
        if re.search(pattern, full_content, re.IGNORECASE):
            analysis['security_controls'].append(security_type)
    
    # Database Operations
    db_patterns = [
        (r'SELECT|INSERT|UPDATE|DELETE', 'sql_operations'),
        (r'find|create|update|delete|save', 'orm_operations'),
        (r'query|execute|fetch', 'database_queries'),
        (r'transaction|commit|rollback', 'transaction_handling'),
        (r'join|union|group_by|order_by', 'complex_queries')
    ]
    
    for pattern, db_type in db_patterns:
        if re.search(pattern, full_content, re.IGNORECASE):
            analysis['database_operations'].append(db_type)
    
    # File Operations
    file_patterns = [
        (r'upload|file|attachment', 'file_uploads'),
        (r'download|serve_file|send_file', 'file_downloads'),
        (r'open|read|write|path', 'file_system_access'),
        (r'image|pdf|document', 'document_processing'),
        (r'temp|tmp|cache', 'temporary_files')
    ]
    
    for pattern, file_type in file_patterns:
        if re.search(pattern, full_content, re.IGNORECASE):
            analysis['file_operations'].append(file_type)
    
    # Error Handling
    error_patterns = [
        (r'try:|except:|catch|finally', 'exception_handling'),
        (r'raise|throw|error', 'error_generation'),
        (r'log|logger|logging', 'error_logging'),
        (r'400|401|403|404|422|429|500', 'http_error_codes'),
        (r'ValidationError|AuthError|PermissionError', 'custom_errors')
    ]
    
    for pattern, error_type in error_patterns:
        if re.search(pattern, full_content, re.IGNORECASE):
            analysis['error_handling'].append(error_type)
    
    # Input Sources Detection
    input_patterns = [
        (r'request\.json|request\.data|request\.form', 'request_body'),
        (r'request\.args|request\.params|query_params', 'query_parameters'),
        (r'request\.headers|headers\[', 'http_headers'),
        (r'path_params|route_params|url_params', 'path_parameters'),
        (r'cookies|session|request\.cookies', 'cookies_session'),
        (r'files|upload|multipart', 'file_uploads')
    ]
    
    for pattern, input_type in input_patterns:
        if re.search(pattern, full_content, re.IGNORECASE):
            analysis['input_sources'].append(input_type)
    
    return analysis

def parse_lambda_code(code):
    """Parse Lambda function code to extract endpoints and their configurations"""
    endpoints = []
    
    # Pattern for Lambda handler function
    handler_pattern = r'def\s+(lambda_handler|handler)\s*\([^)]*\):(.*?)(?=\ndef|\Z)'
    handler_matches = re.findall(handler_pattern, code, re.DOTALL)
    
    # Pattern for API Gateway event handling
    api_patterns = [
        # Standard API Gateway event structure
        r'event\s*\.\s*get\s*\(\s*["\']httpMethod["\']\s*\)',
        r'event\s*\[\s*["\']httpMethod["\']\s*\]',
        # Direct method checks
        r'httpMethod\s*==\s*["\']([^"\']+)["\']',
        r'method\s*==\s*["\']([^"\']+)["\']',
    ]
    
    for handler_name, handler_body in handler_matches:
        # Extract HTTP methods
        methods = set()
        for pattern in api_patterns:
            matches = re.findall(pattern, handler_body, re.IGNORECASE)
            methods.update([m.upper() for m in matches if m])
        
        # If no specific methods found, look for common HTTP method checks
        method_checks = re.findall(r'\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b', handler_body, re.IGNORECASE)
        methods.update([m.upper() for m in method_checks])
        
        if not methods:
            methods = ['POST']  # Default for Lambda APIs
        
        # Extract path parameters
        path_params = re.findall(r'pathParameters["\']?\s*\.\s*get\s*\(\s*["\']([^"\']+)["\']', handler_body)
        path_params.extend(re.findall(r'pathParameters\s*\[\s*["\']([^"\']+)["\']\s*\]', handler_body))
        
        # Extract query parameters
        query_params = re.findall(r'queryStringParameters["\']?\s*\.\s*get\s*\(\s*["\']([^"\']+)["\']', handler_body)
        query_params.extend(re.findall(r'queryStringParameters\s*\[\s*["\']([^"\']+)["\']\s*\]', handler_body))
        
        # Extract body parameters
        body_params = []
        # Look for json.loads patterns
        json_patterns = [
            r'json\.loads\s*\(\s*event\s*\[\s*["\']body["\']\s*\]\s*\)',
            r'json\.loads\s*\(\s*body\s*\)',
        ]
        
        for pattern in json_patterns:
            if re.search(pattern, handler_body):
                # Try to extract field names from subsequent code
                field_patterns = [
                    r'data\s*\.\s*get\s*\(\s*["\']([^"\']+)["\']',
                    r'data\s*\[\s*["\']([^"\']+)["\']\s*\]',
                    r'body_data\s*\.\s*get\s*\(\s*["\']([^"\']+)["\']',
                ]
                
                for field_pattern in field_patterns:
                    fields = re.findall(field_pattern, handler_body)
                    body_params.extend(fields)
        
        # Create sample payload
        sample_payload = {}
        
        # Add body parameters
        for param in body_params:
            if param in ['username', 'user', 'email']:
                sample_payload[param] = 'testuser'
            elif param in ['password', 'pass']:
                sample_payload[param] = 'testpass123'
            elif param in ['title', 'name']:
                sample_payload[param] = 'Test Title'
            elif param in ['body', 'content', 'description']:
                sample_payload[param] = 'Test content'
            elif param in ['id', 'user_id', 'item_id']:
                sample_payload[param] = 1
            else:
                sample_payload[param] = 'test_value'
        
        # Extract expected status codes
        status_codes = re.findall(r'["\']statusCode["\']\s*:\s*(\d+)', handler_body)
        expected_statuses = [int(code) for code in status_codes] if status_codes else [200]
        
        # Determine route path (for Lambda, we'll use a generic path)
        route_path = '/api/lambda-function'
        
        # If we can find specific path info, use it
        path_matches = re.findall(r'["\']resource["\']\s*:\s*["\']([^"\']+)["\']', handler_body)
        if path_matches:
            route_path = path_matches[0]
        
        endpoints.append({
            'route': route_path,
            'methods': list(methods),
            'function_name': handler_name,
            'sample_payload': sample_payload,
            'expected_fields': body_params,
            'path_parameters': path_params,
            'query_parameters': query_params,
            'expected_statuses': expected_statuses,
            'type': 'lambda',
            'function_body': handler_body  # Include the actual code for analysis
        })
    
    return endpoints

def parse_flask_code(code):
    """Parse Flask API code to extract endpoints and their configurations"""
    endpoints = []
    
    # Extract route decorators and function definitions
    route_pattern = r'@app\.route\(["\']([^"\']+)["\'](?:,\s*methods\s*=\s*\[([^\]]+)\])?\)\s*\ndef\s+(\w+)\([^)]*\):'
    matches = re.findall(route_pattern, code, re.MULTILINE)
    
    for route, methods, function_name in matches:
        # Clean up methods
        if methods:
            methods_list = [m.strip().strip('"\'') for m in methods.split(',')]
        else:
            methods_list = ['GET']  # Default method
        
        # Try to extract sample payload from function body
        function_pattern = rf'def\s+{function_name}\([^)]*\):(.*?)(?=\n@|\ndef\s|\nif\s+__name__|$)'
        func_match = re.search(function_pattern, code, re.DOTALL)
        
        sample_payload = {}
        expected_fields = []
        function_body = ""
        
        if func_match:
            function_body = func_match.group(1)
            
            # Look for data.get() calls to identify expected fields
            field_pattern = r'data\.get\(["\']([^"\']+)["\']'
            fields = re.findall(field_pattern, function_body)
            expected_fields = fields
            
            # Create sample payload based on common field names
            for field in fields:
                if field in ['username', 'user', 'email']:
                    sample_payload[field] = 'testuser'
                elif field in ['password', 'pass']:
                    sample_payload[field] = 'testpass123'
                elif field in ['title', 'name']:
                    sample_payload[field] = 'Test Title'
                elif field in ['body', 'content', 'description']:
                    sample_payload[field] = 'Test content'
                elif field in ['id', 'user_id']:
                    sample_payload[field] = 1
                else:
                    sample_payload[field] = 'test_value'
        
        # Determine expected status codes from return statements
        expected_statuses = []
        if func_match:
            func_body = func_match.group(1)
            status_pattern = r'return[^,]+,\s*(\d+)'
            statuses = re.findall(status_pattern, func_body)
            expected_statuses = [int(s) for s in statuses]
        
        if not expected_statuses:
            expected_statuses = [200]  # Default
        
        endpoints.append({
            'route': route,
            'methods': methods_list,
            'function_name': function_name,
            'sample_payload': sample_payload,
            'expected_fields': expected_fields,
            'expected_statuses': expected_statuses,
            'type': 'flask',
            'function_body': function_body  # Include the actual code for analysis
        })
    
    return endpoints

def parse_general_api_code(code):
    """Parse general API code (Express.js, FastAPI, etc.) to extract endpoints"""
    endpoints = []
    
    # Patterns for different frameworks
    patterns = {
        'express': [
            r'app\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
            r'router\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']'
        ],
        'fastapi': [
            r'@app\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
            r'@router\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']'
        ],
        'django': [
            r'path\s*\(\s*["\']([^"\']+)["\'].*?(\w+)\.as_view',
            r'url\s*\(\s*["\']([^"\']+)["\']'
        ]
    }
    
    detected_framework = None
    
    # Detect framework
    if 'express' in code.lower() or 'app.get' in code or 'app.post' in code:
        detected_framework = 'express'
    elif 'fastapi' in code.lower() or '@app.get' in code or '@app.post' in code:
        detected_framework = 'fastapi'
    elif 'django' in code.lower() or 'path(' in code:
        detected_framework = 'django'
    
    if detected_framework:
        for pattern in patterns[detected_framework]:
            matches = re.findall(pattern, code, re.MULTILINE | re.IGNORECASE)
            
            for match in matches:
                if len(match) == 2:
                    if detected_framework in ['express', 'fastapi']:
                        method, route = match
                        methods_list = [method.upper()]
                    else:  # django
                        route, view_name = match
                        methods_list = ['GET', 'POST']  # Default for Django
                        
                    # Extract parameters from route
                    path_params = re.findall(r'[:\{](\w+)[\}]?', route)
                    
                    # Create basic sample payload
                    sample_payload = {'test_field': 'test_value'}
                    
                    # Try to find function body for more context
                    if detected_framework == 'express':
                        func_pattern = rf'{method}\s*\(\s*["\'][^"\']*["\']\s*,\s*.*?\((.*?)\)\s*=>\s*\{{(.*?)\}}'
                        func_match = re.search(func_pattern, code, re.DOTALL)
                        function_body = func_match.group(2) if func_match else ""
                    else:
                        function_body = ""
                    
                    endpoints.append({
                        'route': route,
                        'methods': methods_list,
                        'function_name': f'{detected_framework}_endpoint',
                        'sample_payload': sample_payload,
                        'expected_fields': ['test_field'],
                        'expected_statuses': [200],
                        'type': detected_framework,
                        'path_parameters': path_params,
                        'function_body': function_body
                    })
    
    return endpoints

def parse_api_code(code):
    """Unified API code parser that handles multiple frameworks"""
    endpoints = []
    
    # Try Flask parsing first
    flask_endpoints = parse_flask_code(code)
    if flask_endpoints:
        endpoints.extend(flask_endpoints)
    
    # Try Lambda parsing
    lambda_endpoints = parse_lambda_code(code)
    if lambda_endpoints:
        endpoints.extend(lambda_endpoints)
    
    # Try general framework parsing if nothing found
    if not endpoints:
        general_endpoints = parse_general_api_code(code)
        endpoints.extend(general_endpoints)
    
    return endpoints

def enhance_endpoints_with_context(endpoints, context_info):
    """Enhance detected endpoints with context information (cURL, URLs, etc.)"""
    enhanced_endpoints = endpoints.copy()
    
    if not context_info.strip():
        return enhanced_endpoints
    
    # Try to parse context as cURL command
    curl_info, error = parse_curl_command(context_info)
    if curl_info:
        # Match cURL info with detected endpoints or create new one
        curl_endpoint = {
            'route': urlparse(curl_info['url']).path or '/api/endpoint',
            'methods': [curl_info['method']],
            'function_name': 'curl_derived_endpoint',
            'sample_payload': curl_info['data'] if curl_info['data'] else {},
            'expected_fields': list(curl_info['data'].keys()) if isinstance(curl_info['data'], dict) else [],
            'expected_statuses': [200],
            'type': 'curl_derived',
            'full_url': curl_info['url'],
            'headers': curl_info['headers'],
            'function_body': ''
        }
        
        # Check if this matches any existing endpoint
        matched = False
        for i, endpoint in enumerate(enhanced_endpoints):
            if (endpoint['route'] == curl_endpoint['route'] or 
                curl_info['method'] in endpoint['methods']):
                # Enhance existing endpoint with cURL data
                enhanced_endpoints[i]['full_url'] = curl_info['url']
                enhanced_endpoints[i]['headers'] = {**endpoint.get('headers', {}), **curl_info['headers']}
                if curl_info['data'] and isinstance(curl_info['data'], dict):
                    enhanced_endpoints[i]['sample_payload'].update(curl_info['data'])
                matched = True
                break
        
        if not matched:
            enhanced_endpoints.append(curl_endpoint)
    
    # Look for URLs in context
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+[^\s<>"{}|\\^`\[\].,;]'
    urls = re.findall(url_pattern, context_info)
    
    for url in urls:
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # Update base URLs for existing endpoints
        for endpoint in enhanced_endpoints:
            if not endpoint.get('full_url'):
                endpoint['full_url'] = base_url + endpoint['route']
    
    return enhanced_endpoints

def generate_context_aware_test_cases(client, api_endpoint, http_method, sample_payload, custom_headers, code_analysis, endpoint_details):
    """Generate test cases based on actual code analysis and context - FIXED VERSION"""
    
    # CRITICAL CHECK: Ensure client is valid
    if not client:
        st.error("❌ OpenAI client is not initialized. Please check your API key.")
        return []
    
    system_prompt = """You are an expert API security tester with deep knowledge of application vulnerabilities and attack patterns. Your task is to generate highly targeted, context-aware test cases that includes flowlevel cases, edge cases, boundary cases etc.. based on ACTUAL CODE ANALYSIS and real-world attack scenarios.

CRITICAL INSTRUCTIONS:
1. ANALYZE THE PROVIDED CODE CONTEXT THOROUGHLY
2. Generate test cases that are SPECIFIC to the actual code implementation
3. Focus on REAL vulnerabilities that exist in the provided code
4. Cover ALL security dimensions: Flow, Boundary, Edge Cases, Injection, Authentication, Authorization, Business Logic

COMPREHENSIVE TEST COVERAGE REQUIRED:
- **Flow Level**: Test request sequences, state transitions, operation dependencies
- **Boundary Testing**: Field limits, numeric boundaries, array sizes, length constraints  
- **Edge Cases**: Empty inputs, null values, special characters, Unicode, malformed data
- **Security**: All injection types, auth bypass, privilege escalation, CSRF, XSS
- **Business Logic**: Role checks, permission validation, state-dependent operations
- **Error Handling**: Exception scenarios, error message leakage, stack traces

OUTPUT FORMAT (use this EXACT format for each test):
TEST_NAME: [descriptive name based on actual code analysis]
METHOD: [HTTP method]
PAYLOAD: [specific test payload]
HEADERS: [any special headers]
EXPECTED_STATUS: [expected HTTP status code]
DESCRIPTION: [what vulnerability/scenario this tests and WHY based on code analysis]
RISK_LEVEL: [LOW/MEDIUM/HIGH/CRITICAL]
ATTACK_VECTOR: [specific attack technique being tested]
CODE_TARGET: [specific part of code this targets]
---

QUALITY REQUIREMENTS:
- Each test must be JUSTIFIED by the actual code implementation
- Generate comprehensive coverage (typically 40-100+ tests for thorough analysis)
- Target REAL attack vectors that could exploit the specific code
- Include both positive and negative test cases
- Vary payloads based on actual field validation and business logic
- Test ALL input sources identified in the code (body, query, path, headers)
"""

    user_prompt = f"""ENDPOINT TO TEST:
URL: {api_endpoint}
METHOD: {http_method}
Sample Payload: {json.dumps(sample_payload, indent=2)}
Headers: {json.dumps(custom_headers, indent=2)}

DETAILED CODE ANALYSIS:
{json.dumps(code_analysis, indent=2)}

SPECIFIC ENDPOINT DETAILS:
Route: {endpoint_details.get('route', 'N/A')}
Function: {endpoint_details.get('function_name', 'N/A')}
Framework: {endpoint_details.get('type', 'N/A')}
Expected Fields: {endpoint_details.get('expected_fields', [])}
Path Parameters: {endpoint_details.get('path_parameters', [])}
Query Parameters: {endpoint_details.get('query_parameters', [])}

ACTUAL FUNCTION CODE:
{endpoint_details.get('function_body', 'No function body available')}

MISSION: Generate comprehensive, code-specific security test cases that:
1. Target the ACTUAL vulnerabilities present in this specific implementation
2. Test all identified input sources and validation patterns
3. Exploit weaknesses in the detected authentication and authorization mechanisms  
4. Challenge the business logic flows identified in the code
5. Test boundary conditions based on actual field constraints
6. Attempt all relevant injection attacks based on detected database/file operations
7. Test error handling and information disclosure scenarios
8. Validate security controls and bypass attempts

Generate as many test cases as needed for COMPLETE security coverage of this specific endpoint (typically 50-150+ tests for thorough analysis). Each test should be directly justified by the code analysis provided."""

    try:
        # FIXED: Use proper model name and error handling
        response = client.chat.completions.create(
            model="gpt-4o-mini",  # Make sure model name is correct
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.1,  
            max_tokens=8000
        )
        
        if not response or not response.choices:
            st.error("❌ No response received from OpenAI API")
            return []
        
        raw_response = response.choices[0].message.content.strip()
        
        if not raw_response:
            st.error("❌ Empty response from OpenAI API")
            return []
        
        test_cases = parse_context_aware_tests(raw_response, sample_payload, custom_headers)
        return test_cases
        
    except Exception as e:
        st.error(f"❌ Failed to generate context-aware tests: {e}")
        st.error(f"Error details: {type(e).__name__}: {str(e)}")
        return []

def parse_context_aware_tests(raw_text, sample_payload, custom_headers):
    """Parse context-aware test cases from GPT response with validation"""
    
    if not raw_text or raw_text.strip() == "":
        return []
    
    test_cases = []
    test_blocks = raw_text.split('---')
    
    for block in test_blocks:
        if not block.strip():
            continue
            
        test_case = {}
        
        patterns = {
            'name': r'TEST_NAME:\s*(.+?)(?:\n|$)',
            'method': r'METHOD:\s*(.+?)(?:\n|$)', 
            'payload': r'PAYLOAD:\s*(.+?)(?=\nHEADERS:|\nEXPECTED_STATUS:|\nDESCRIPTION:|$)',
            'headers': r'HEADERS:\s*(.+?)(?=\nEXPECTED_STATUS:|\nDESCRIPTION:|$)',
            'expected_status': r'EXPECTED_STATUS:\s*(.+?)(?:\n|$)',
            'description': r'DESCRIPTION:\s*(.+?)(?=\nRISK_LEVEL:|\nATTACK_VECTOR:|$)',
            'risk_level': r'RISK_LEVEL:\s*(.+?)(?:\n|$)',
            'attack_vector': r'ATTACK_VECTOR:\s*(.+?)(?:\n|$)',
            'code_target': r'CODE_TARGET:\s*(.+?)(?:\n|$)'
        }
        
        for field, pattern in patterns.items():
            match = re.search(pattern, block, re.DOTALL | re.IGNORECASE)
            if match:
                value = match.group(1).strip()
                
                if field == 'method':
                    # FIXED: Validate HTTP method
                    valid_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
                    method = value.upper()
                    if method not in valid_methods:
                        method = 'GET'  # Default to GET for invalid methods
                    test_case['method'] = method
                elif field == 'payload':
                    test_case['payload'] = parse_payload_value(value, sample_payload)
                elif field == 'headers':
                    test_case['headers'] = parse_headers_value(value, custom_headers)
                elif field == 'expected_status':
                    try:
                        # FIXED: Better status code parsing
                        status_match = re.findall(r'\b(\d{3})\b', value)
                        if status_match:
                            test_case['expected_status_code'] = int(status_match[0])
                        else:
                            test_case['expected_status_code'] = 200
                    except:
                        test_case['expected_status_code'] = 200
                else:
                    test_case[field] = value
        
        # FIXED: Validate essential fields before adding
        required_fields = ['name', 'method', 'expected_status_code']
        if all(key in test_case for key in required_fields):
            # Set defaults for missing fields
            if 'payload' not in test_case:
                test_case['payload'] = sample_payload
            if 'headers' not in test_case:
                test_case['headers'] = custom_headers or {}
            if 'risk_level' not in test_case:
                test_case['risk_level'] = 'MEDIUM'
            if 'description' not in test_case:
                test_case['description'] = 'Context-aware security test'
            if 'attack_vector' not in test_case:
                test_case['attack_vector'] = 'General security testing'
            if 'code_target' not in test_case:
                test_case['code_target'] = 'General endpoint testing'
                
            test_cases.append(test_case)
        else:
            # Log missing fields for debugging
            missing = [field for field in required_fields if field not in test_case]
            print(f"Skipping test case due to missing fields: {missing}")
    
    return test_cases

def parse_payload_value(payload_str, default_payload):
    """Parse payload string into appropriate format"""
    
    if not payload_str or payload_str.lower() in ['none', 'null', 'empty']:
        return None
    
    try:
        return json.loads(payload_str)
    except:
        pass
    
    if payload_str.startswith('{') and payload_str.endswith('}'):
        try:
            fixed = payload_str.replace("'", '"')
            fixed = re.sub(r'(\w+):', r'"\1":', fixed)
            return json.loads(fixed)
        except:
            pass
    
    return {"data": payload_str}

def parse_headers_value(headers_str, default_headers):
    """Parse headers string into dict format"""
    
    if not headers_str or headers_str.lower() in ['none', 'null', 'empty', 'default']:
        return default_headers
    
    try:
        return json.loads(headers_str)
    except:
        pass
    
    headers = {}
    for line in headers_str.split(','):
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip()] = value.strip()
    
    return headers if headers else default_headers

def create_endpoint_selector(endpoints, base_url):
    """Create a selector for available endpoints"""
    
    if not endpoints:
        return None
    
    # Create options for selectbox
    options = []
    for endpoint in endpoints:
        for method in endpoint['methods']:
            # Use full_url if available, otherwise construct from base_url
            if endpoint.get('full_url'):
                full_url = endpoint['full_url']
            elif base_url:
                full_url = f"{base_url.rstrip('/')}{endpoint['route']}"
            else:
                full_url = endpoint['route']
            
            display_name = f"{method} {endpoint['route']}"
            if endpoint.get('type'):
                display_name += f" ({endpoint['type'].title()})"
            
            options.append({
                'display': display_name,
                'url': full_url,
                'method': method,
                'payload': endpoint['sample_payload'],
                'expected_statuses': endpoint['expected_statuses'],
                'type': endpoint.get('type', 'unknown'),
                'headers': endpoint.get('headers', {}),
                'endpoint_details': endpoint
            })
    
    return options

def execute_tests(test_cases, api_endpoint, base_headers):
    """Execute all test cases and return results - FIXED VERSION"""
    
    results = []
    stats = {"total": 0, "passed": 0, "failed": 0, "errors": 0}
    attack_vector_stats = {}
    risk_level_stats = {}
    
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    for i, test_case in enumerate(test_cases):
        progress_bar.progress((i + 1) / len(test_cases))
        status_text.text(f"Executing test {i+1}/{len(test_cases)}: {test_case['name']}")
        
        attack_vector = test_case.get("attack_vector", "unknown")
        risk_level = test_case.get("risk_level", "MEDIUM")
        
        # Track attack vector stats
        if attack_vector not in attack_vector_stats:
            attack_vector_stats[attack_vector] = {"total": 0, "passed": 0, "failed": 0}
        attack_vector_stats[attack_vector]["total"] += 1
        
        # Track risk level stats
        if risk_level not in risk_level_stats:
            risk_level_stats[risk_level] = {"total": 0, "passed": 0, "failed": 0}
        risk_level_stats[risk_level]["total"] += 1
        
        stats["total"] += 1
        
        try:
            method = test_case.get("method", "GET")
            payload = test_case.get("payload")
            headers = {**base_headers, **(test_case.get("headers", {}) or {})}
            expected_status = test_case.get("expected_status_code", 200)
            
            # FIXED: Add better error handling and logging
            try:
                response = make_request(method, api_endpoint, payload, headers)
                
                # FIXED: Check if response is valid
                if response is None:
                    raise Exception("No response received from server")
                
                status_matches = response.status_code == expected_status
                
                if status_matches:
                    stats["passed"] += 1
                    attack_vector_stats[attack_vector]["passed"] += 1
                    risk_level_stats[risk_level]["passed"] += 1
                    test_result = "PASS"
                else:
                    stats["failed"] += 1
                    attack_vector_stats[attack_vector]["failed"] += 1
                    risk_level_stats[risk_level]["failed"] += 1
                    test_result = "FAIL"
                
                # FIXED: Better response body handling
                try:
                    response_body = response.text[:500] if response.text else "Empty response"
                except:
                    response_body = "Could not read response body"
                
                results.append({
                    "test_name": test_case["name"],
                    "attack_vector": attack_vector,
                    "code_target": test_case.get("code_target", ""),
                    "description": test_case.get("description", ""),
                    "method": method,
                    "payload": str(payload) if payload else "",
                    "headers": str(test_case.get("headers", {})),
                    "expected_status": expected_status,
                    "actual_status": response.status_code,
                    "response_body": response_body,
                    "response_time": response.elapsed.total_seconds(),
                    "status_matches": status_matches,
                    "risk_level": risk_level,
                    "test_result": test_result,
                    "error": None  # No error in this case
                })
                
            except requests.exceptions.RequestException as req_error:
                # FIXED: Handle specific request errors
                stats["errors"] += 1
                attack_vector_stats[attack_vector]["failed"] += 1
                risk_level_stats[risk_level]["failed"] += 1
                
                results.append({
                    "test_name": test_case["name"],
                    "attack_vector": attack_vector,
                    "code_target": test_case.get("code_target", ""),
                    "description": test_case.get("description", ""),
                    "method": method,
                    "payload": str(payload) if payload else "",
                    "headers": str(test_case.get("headers", {})),
                    "expected_status": expected_status,
                    "actual_status": "Request Error",
                    "response_body": "",
                    "response_time": 0,
                    "status_matches": False,
                    "risk_level": risk_level,
                    "test_result": "ERROR",
                    "error": f"Request Error: {str(req_error)}"
                })
            
        except Exception as e:
            # FIXED: Better general error handling
            stats["errors"] += 1
            attack_vector_stats[attack_vector]["failed"] += 1
            risk_level_stats[risk_level]["failed"] += 1
            
            results.append({
                "test_name": test_case["name"],
                "attack_vector": attack_vector,
                "code_target": test_case.get("code_target", ""),
                "description": test_case.get("description", ""),
                "method": method if 'method' in locals() else "UNKNOWN",
                "payload": str(payload) if 'payload' in locals() and payload else "",
                "headers": str(test_case.get("headers", {})),
                "expected_status": expected_status if 'expected_status' in locals() else "UNKNOWN",
                "actual_status": "Exception",
                "response_body": "",
                "response_time": 0,
                "status_matches": False,
                "risk_level": risk_level,
                "test_result": "ERROR",
                "error": f"Test Execution Error: {str(e)}"
            })
            
            # FIXED: Log the error for debugging
            print(f"Error in test '{test_case['name']}': {str(e)}")
    
    status_text.text("✅ Test execution completed!")
    return results, stats, attack_vector_stats, risk_level_stats

def make_request(method, url, payload=None, headers=None):
    """Make HTTP request with improved error handling"""
    
    # Validate URL
    if not url or not url.strip():
        raise ValueError("URL cannot be empty")
    
    # Ensure URL has proper protocol
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Default headers
    default_headers = {"Content-Type": "application/json"}
    if headers:
        default_headers.update(headers)
    
    request_kwargs = {
        "url": url,
        "headers": default_headers,
        "timeout": 30,  # Increased timeout
        "verify": True,  # SSL verification
        "allow_redirects": True
    }
    
    # Handle different methods and payloads
    method_upper = method.upper()
    
    if method_upper in ["POST", "PUT", "PATCH"] and payload is not None:
        if isinstance(payload, dict):
            request_kwargs["json"] = payload
        elif isinstance(payload, str):
            try:
                # Try to parse as JSON first
                parsed_payload = json.loads(payload)
                request_kwargs["json"] = parsed_payload
            except json.JSONDecodeError:
                # If not JSON, send as data
                request_kwargs["data"] = payload
                request_kwargs["headers"]["Content-Type"] = "text/plain"
        else:
            request_kwargs["data"] = str(payload)
    elif method_upper == "GET" and payload:
        if isinstance(payload, dict):
            request_kwargs["params"] = payload
        else:
            request_kwargs["params"] = {"q": str(payload)}
    
    # Make the request
    try:
        response = requests.request(method_upper, **request_kwargs)
        return response
    except requests.exceptions.Timeout:
        raise requests.exceptions.RequestException("Request timed out")
    except requests.exceptions.ConnectionError:
        raise requests.exceptions.RequestException("Connection error - check URL and network")
    except requests.exceptions.HTTPError as e:
        raise requests.exceptions.RequestException(f"HTTP error: {e}")
    except Exception as e:
        raise requests.exceptions.RequestException(f"Unexpected error: {e}")

def create_excel_download(results, stats, attack_vector_stats, risk_level_stats):
    """Create Excel file with detailed results"""
    
    # Create a BytesIO buffer
    buffer = BytesIO()
    
    with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
        # Summary sheet
        summary_data = {
            "Metric": ["Total Tests", "Passed", "Failed", "Errors", "Success Rate (%)"],
            "Value": [
                stats["total"],
                stats["passed"], 
                stats["failed"],
                stats["errors"],
                round((stats["passed"] / stats["total"] * 100) if stats["total"] > 0 else 0, 2)
            ]
        }
        summary_df = pd.DataFrame(summary_data)
        summary_df.to_excel(writer, sheet_name='Summary', index=False)
        
        # Attack vector breakdown sheet
        attack_data = []
        for attack_vector, av_stats in attack_vector_stats.items():
            attack_data.append({
                "Attack Vector": attack_vector,
                "Total Tests": av_stats["total"],
                "Passed": av_stats["passed"],
                "Failed": av_stats["failed"],
                "Success Rate (%)": round((av_stats["passed"] / av_stats["total"] * 100) if av_stats["total"] > 0 else 0, 2)
            })
        attack_df = pd.DataFrame(attack_data)
        attack_df.to_excel(writer, sheet_name='Attack Vectors', index=False)
        
        # Risk level breakdown sheet
        risk_data = []
        for risk_level, risk_stats in risk_level_stats.items():
            risk_data.append({
                "Risk Level": risk_level,
                "Total Tests": risk_stats["total"],
                "Passed": risk_stats["passed"],
                "Failed": risk_stats["failed"],
                "Success Rate (%)": round((risk_stats["passed"] / risk_stats["total"] * 100) if risk_stats["total"] > 0 else 0, 2)
            })
        risk_df = pd.DataFrame(risk_data)
        risk_df.to_excel(writer, sheet_name='Risk Levels', index=False)
        
        # Detailed results sheet
        results_df = pd.DataFrame(results)
        results_df.to_excel(writer, sheet_name='Detailed Results', index=False)
        
        # Failed tests only sheet
        failed_tests = [r for r in results if not r.get("status_matches", False)]
        if failed_tests:
            failed_df = pd.DataFrame(failed_tests)
            failed_df.to_excel(writer, sheet_name='Failed Tests', index=False)
        
        # High risk failures sheet
        high_risk_failures = [r for r in results if not r.get("status_matches", False) and r.get("risk_level", "").upper() in ["HIGH", "CRITICAL"]]
        if high_risk_failures:
            high_risk_df = pd.DataFrame(high_risk_failures)
            high_risk_df.to_excel(writer, sheet_name='High Risk Failures', index=False)
    
    buffer.seek(0)
    return buffer

# Main Streamlit App
def main():
    st.markdown('<div class="main-header">🔒 Context-Aware API Security Tester</div>', unsafe_allow_html=True)
    
    # FIXED: Better API key handling and validation
    user_api_key = st.text_input("Enter your OpenAI API key:", type="password", help="Your OpenAI API key (starts with sk-)")
    
    if not user_api_key:
        st.warning("Please enter your OpenAI API key to continue.")
        st.info("""
        **Need an OpenAI API key?**
        1. Go to [OpenAI Platform](https://platform.openai.com/api-keys)
        2. Sign in or create an account
        3. Create a new API key
        4. Copy and paste it here
        
        **Note:** Make sure your API key has sufficient credits and access to GPT models.
        """)
        return
    
    # FIXED: Better client initialization with detailed error messages
    with st.spinner("🔄 Validating OpenAI API key..."):
        client, result = initialize_openai_client(user_api_key)
        
    if not client:
        st.error(f"❌ OpenAI API connection failed: {result}")
        if "Invalid API key format" in str(result):
            st.info("💡 Make sure your API key starts with 'sk-' and is copied correctly.")
        elif "validation failed" in str(result):
            st.info("💡 Possible issues:\n- API key might be invalid or expired\n- Insufficient credits in your OpenAI account\n- Network connectivity issues")
        elif "quota" in str(result).lower():
            st.error("💳 Your OpenAI account has exceeded the API quota. Please check your billing settings.")
        
        return
    
    st.success("✅ OpenAI API connected successfully!")
    
    # Initialize session state
    if 'parsed_endpoints' not in st.session_state:
        st.session_state.parsed_endpoints = None
    if 'code_analysis' not in st.session_state:
        st.session_state.code_analysis = None
    if 'test_config' not in st.session_state:
        st.session_state.test_config = None
    if 'test_cases' not in st.session_state:
        st.session_state.test_cases = None
    if 'test_results' not in st.session_state:
        st.session_state.test_results = None
    
    # Main Input Section
    st.header("📝 API Code Input")
    
    # Framework detection info
    st.info("""
    **🎯 Context-Aware Analysis - Supported Technologies:**
    - 🐍 **Flask/FastAPI/Django** - Python web frameworks
    - ⚡ **AWS Lambda** - Serverless functions with API Gateway
    - 🟢 **Express.js/Node.js** - JavaScript backend frameworks  
    - ☕ **Spring Boot** - Java enterprise applications
    - 🔷 **ASP.NET Core** - .NET web APIs
    - 📦 **Generic REST APIs** - Any HTTP-based API implementation
    
    **🧠 Intelligent Analysis Features:**
    - **Code Context Analysis** - Understands your actual implementation
    - **Security Pattern Detection** - Identifies auth, validation, business logic
    - **Vulnerability Mapping** - Maps code patterns to attack vectors
    - **Flow Analysis** - Understands request/response patterns
    """)
    
    # Input method tabs
    input_tab1, input_tab2 = st.tabs(["📝 Paste Code", "📁 Upload Files"])
    
    with input_tab1:
        # Code input section
        api_code = st.text_area(
            "Paste your API code here:",
            height=350,
            placeholder="""# Your complete API implementation - the more complete, the better the analysis!

# Flask Example:
@app.route("/api/users/<int:user_id>", methods=["GET", "PUT"])
@login_required
def user_profile(user_id):
    if not current_user.is_admin and current_user.id != user_id:
        return {"error": "Access denied"}, 403
    
    if request.method == "PUT":
        data = request.get_json()
        email = data.get("email")
        if email and not validate_email(email):
            return {"error": "Invalid email"}, 400
            
        user = User.query.filter_by(id=user_id).first()
        if user:
            user.email = email
            db.session.commit()
            return {"status": "updated"}, 200
    
    return User.query.get_or_404(user_id).to_dict()

# AWS Lambda Example:
def lambda_handler(event, context):
    method = event['httpMethod']
    path_params = event.get('pathParameters', {})
    
    if method == 'POST':
        body = json.loads(event['body'])
        username = body.get('username')
        password = body.get('password')
        
        if not username or len(username) < 3:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Username too short'})
            }
            
        # Authentication logic here
        if authenticate_user(username, password):
            token = generate_jwt_token(username)
            return {
                'statusCode': 200,
                'body': json.dumps({'token': token})
            }
        else:
            return {
                'statusCode': 401,
                'body': json.dumps({'error': 'Invalid credentials'})
            }
""",
            help="Paste your complete API code. The more detailed the code, the more specific and targeted the security tests will be.",
            key="code_input"
        )
    
    with input_tab2:
        # File upload section
        st.markdown('<div class="upload-section">', unsafe_allow_html=True)
        uploaded_files = st.file_uploader(
            "Upload your API code files:",
            accept_multiple_files=True,
            type=['py', 'js', 'ts', 'java', 'php', 'rb', 'go', 'rs', 'txt', 'zip'],
            help="Upload individual code files or ZIP archives containing your complete API implementation"
        )
        st.markdown('</div>', unsafe_allow_html=True)
        
        api_code_from_files = ""
        if uploaded_files:
            with st.spinner("Reading and analyzing uploaded files..."):
                file_content, file_info = read_uploaded_files(uploaded_files)
                api_code_from_files = file_content
                
                if file_info:
                    st.success(f"✅ Successfully read {len(file_info)} files")
                    
                    # Show file summary
                    with st.expander("📋 Uploaded Files Summary", expanded=False):
                        for file in file_info:
                            st.write(f"**{file['name']}** - {file['size']} characters ({file['type']})")
                    
                    # Show preview of content
                    with st.expander("👀 Code Preview", expanded=False):
                        st.code(file_content[:2000] + "..." if len(file_content) > 2000 else file_content, 
                               language='python')
    
    # Combine code from both sources
    final_code = api_code if api_code.strip() else api_code_from_files
    
    # Context Information Section
    st.header("🔧 Additional Context (Recommended)")
    st.info("""
    **🚀 Enhance Analysis with Real-World Context:**
    - 📡 **cURL Commands** - Actual API calls you've tested
    - 🔗 **API URLs** - Complete endpoint URLs with domains
    - 📄 **API Documentation** - Swagger/OpenAPI specifications
    - 🔑 **Authentication Examples** - Headers, tokens, API keys
    - 🌐 **Base URLs** - Production/staging server endpoints
    - 📊 **Expected Behaviors** - Normal vs error responses
    
    **💡 Pro Tip:** The more context you provide, the more targeted and effective the security tests become!
    """)
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        context_info = st.text_area(
            "Additional Context (cURL commands, URLs, documentation, etc.):",
            height=150,
            placeholder="""Real-world examples that help create better tests:

# Example cURL command:
curl -X POST "https://api.myapp.com/auth/login" \
  -H "Content-Type: application/json" \
  -H "X-API-Version: 1.0" \
  -d '{"username":"john@example.com","password":"secure123"}'

# Base URL:
https://api.myapp.com

# Authentication:
- Uses JWT tokens in Authorization header
- Admin endpoints require "X-Admin-Key" header
- Rate limit: 100 requests/minute per IP

# Expected responses:
- Success: 200 with JSON
- Validation errors: 422 with error details
- Auth failures: 401 with error message

# Business rules:
- Users can only access their own data unless admin
- Email must be unique in system
- Passwords must be at least 8 characters
""",
            help="This context helps generate tests that target your specific implementation and real attack scenarios",
            key="context_input"
        )
    
    with col2:
        base_url = st.text_input(
            "Base URL:",
            value="",
            placeholder="https://api.example.com",
            help="Primary base URL where your API is deployed",
            key="base_url_input"
        )
    
    # Analysis Button
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        analyze_button = st.button("Analyze Code and Generate Endpoints", type="primary", use_container_width=True, disabled=not final_code.strip())
    
    # Analyze API code
    if analyze_button and final_code.strip():
        with st.spinner("🔍 Performing deep code analysis and security intelligence gathering..."):
            # Parse the main code
            endpoints = parse_api_code(final_code)
            
            # Perform comprehensive code analysis
            code_analysis = analyze_code_context(final_code, context_info)
            
            # Enhance with context information
            if context_info.strip() or base_url.strip():
                context_combined = f"{context_info}\nBase URL: {base_url}".strip()
                endpoints = enhance_endpoints_with_context(endpoints, context_combined)
            
            st.session_state.parsed_endpoints = endpoints
            st.session_state.code_analysis = code_analysis
            
            if endpoints:
                frameworks = list(set([ep.get('type', 'unknown') for ep in endpoints]))
                st.success(f"✅ Found {len(endpoints)} endpoint(s) across {len(frameworks)} framework(s): {', '.join(frameworks).title()}")
                
                # Show detailed analysis results
                col1, col2 = st.columns(2)
                
                with col1:
                    st.subheader("🔍 Code Analysis Results")
                    
                    if code_analysis['authentication_methods']:
                        st.write(f"🔐 **Authentication:** {', '.join(code_analysis['authentication_methods'])}")
                    if code_analysis['validation_patterns']:
                        st.write(f"✅ **Validation:** {', '.join(code_analysis['validation_patterns'])}")
                    if code_analysis['security_controls']:
                        st.write(f"🛡️ **Security Controls:** {', '.join(code_analysis['security_controls'])}")
                    if code_analysis['database_operations']:
                        st.write(f"💾 **Database Ops:** {', '.join(code_analysis['database_operations'])}")
                
                with col2:
                    st.subheader("🎯 Attack Surface Analysis")
                    
                    if code_analysis['business_logic']:
                        st.write(f"🧠 **Business Logic:** {', '.join(code_analysis['business_logic'])}")
                    if code_analysis['input_sources']:
                        st.write(f"📥 **Input Sources:** {', '.join(code_analysis['input_sources'])}")
                    if code_analysis['error_handling']:
                        st.write(f"⚠️ **Error Handling:** {', '.join(code_analysis['error_handling'])}")
                    if code_analysis['file_operations']:
                        st.write(f"📁 **File Operations:** {', '.join(code_analysis['file_operations'])}")
                
                # Framework breakdown
                framework_counts = {}
                for ep in endpoints:
                    fw = ep.get('type', 'unknown')
                    framework_counts[fw] = framework_counts.get(fw, 0) + 1
                
                breakdown = " | ".join([f"{fw.title()}: {count}" for fw, count in framework_counts.items()])
                st.info(f"📊 **Framework Breakdown:** {breakdown}")
                
                # Context enhancements
                context_enhanced = [ep for ep in endpoints if ep.get('full_url') or ep.get('headers')]
                if context_enhanced:
                    st.info(f"🔧 **Context Enhanced:** {len(context_enhanced)} endpoints enhanced with additional context")
                    
            else:
                st.error("❌ No API endpoints found. Please check your code format or provide additional context.")
                st.info("""
                **Troubleshooting Tips:**
                - Ensure your code contains actual API route definitions (Flask @app.route, Lambda handlers, etc.)
                - Try adding cURL commands or API URLs in the context section
                - Check that your code includes the actual function implementations, not just imports
                - Make sure file uploads contain actual code files, not just documentation
                """)
    
    # Endpoint Selection & Configuration
    if st.session_state.parsed_endpoints and st.session_state.code_analysis:
        endpoints = st.session_state.parsed_endpoints
        code_analysis = st.session_state.code_analysis
        endpoint_options = create_endpoint_selector(endpoints, base_url)
        
        if endpoint_options:
            st.header("Endpoint Configuration")
            
            # Endpoint selector
            selected_option = st.selectbox(
                "Select an endpoint for comprehensive security testing:",
                options=range(len(endpoint_options)),
                format_func=lambda x: endpoint_options[x]['display'],
                help="Choose which endpoint you want to perform deep security analysis on"
            )
            
            if selected_option is not None:
                selected_endpoint = endpoint_options[selected_option]
                endpoint_details = selected_endpoint['endpoint_details']
                
                # Display comprehensive endpoint analysis
                st.subheader("📋 Endpoint Report")
                
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.write(f"**URL:** `{selected_endpoint['url']}`")
                    st.write(f"**Method:** `{selected_endpoint['method']}`")
                    st.write(f"**Framework:** `{selected_endpoint['type'].title()}`")
                
                with col2:
                    st.write(f"**Function:** `{endpoint_details.get('function_name', 'N/A')}`")
                    expected_fields = endpoint_details.get('expected_fields', [])
                    st.write(f"**Expected Fields:** {len(expected_fields)}")
                    if expected_fields:
                        st.write(f"*{', '.join(expected_fields[:5])}{'...' if len(expected_fields) > 5 else ''}*")
                
                with col3:
                    st.write(f"**Expected Status Codes:** {selected_endpoint['expected_statuses']}")
                    path_params = endpoint_details.get('path_parameters', [])
                    query_params = endpoint_details.get('query_parameters', [])
                    st.write(f"**Parameters:** Path({len(path_params)}) Query({len(query_params)})")
                
                # Security Analysis for this endpoint
                if endpoint_details.get('function_body'):
                    with st.expander("🔍 Security Analysis for this Endpoint", expanded=True):
                        func_body = endpoint_details['function_body']
                        
                        # Analyze specific patterns in this function
                        security_findings = []
                        
                        if 'password' in func_body.lower() and 'hash' not in func_body.lower():
                            security_findings.append("⚠️ **Password Handling**: Potential plaintext password handling detected")
                        
                        if 'sql' in func_body.lower() and 'parameterized' not in func_body.lower():
                            security_findings.append("🔴 **SQL Injection Risk**: Direct SQL queries detected without parameterization")
                        
                        if 'admin' in func_body.lower() and 'check' not in func_body.lower():
                            security_findings.append("🟠 **Authorization Risk**: Admin functionality may lack proper authorization checks")
                        
                        if 'json.loads' in func_body and 'validate' not in func_body.lower():
                            security_findings.append("🟡 **Input Validation**: JSON parsing without validation detected")
                        
                        if re.search(r'return.*error', func_body, re.IGNORECASE):
                            security_findings.append("ℹ️ **Error Handling**: Error responses detected - potential information disclosure")
                        
                        if security_findings:
                            for finding in security_findings:
                                st.markdown(finding)
                        else:
                            st.success("✅ No obvious security concerns detected in this endpoint")
                
                # Auto-detected sample payload with intelligent enhancement
                st.subheader("detected Payload Configuration")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write("**Auto-detected Sample Payload:**")
                    if selected_endpoint['payload']:
                        st.json(selected_endpoint['payload'])
                    else:
                        st.info("No payload detected (likely GET endpoint)")
                
                with col2:
                    st.write("**Detected Input Sources:**")
                    input_sources = code_analysis.get('input_sources', [])
                    if input_sources:
                        for source in input_sources:
                            st.write(f"• {source.replace('_', ' ').title()}")
                    else:
                        st.info("No specific input sources detected")
                
                # Configuration section
                st.subheader("⚙️ Edit Test Configuration")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    # Allow manual payload editing with intelligent suggestions
                    payload_help = "Modify the auto-detected payload. "
                    if endpoint_details.get('expected_fields'):
                        payload_help += f"Expected fields: {', '.join(endpoint_details['expected_fields'])}"
                    
                    manual_payload_edit = st.text_area(
                        "Edit Sample Payload (JSON):",
                        value=json.dumps(selected_endpoint['payload'], indent=2) if selected_endpoint['payload'] else "{}",
                        help=payload_help,
                        height=200
                    )
                
                with col2:
                    # Custom headers with intelligent defaults
                    default_headers = {"Content-Type": "application/json"}
                    if selected_endpoint.get('headers'):
                        default_headers.update(selected_endpoint['headers'])
                    
                    # Add authentication headers based on analysis
                    if 'token_auth' in code_analysis.get('authentication_methods', []):
                        default_headers["Authorization"] = "Bearer your_token_here"
                    if 'api_key' in code_analysis.get('authentication_methods', []):
                        default_headers["X-API-Key"] = "your_api_key_here"
                    
                    custom_headers_input = st.text_area(
                        "Custom Headers (JSON):",
                        value=json.dumps(default_headers, indent=2),
                        help="Headers configured based on detected authentication methods",
                        height=200
                    )
                
                # Parse the inputs
                try:
                    sample_payload = json.loads(manual_payload_edit) if manual_payload_edit.strip() else {}
                except json.JSONDecodeError:
                    st.error("❌ Invalid JSON in payload. Please check your format.")
                    return
                
                try:
                    custom_headers = json.loads(custom_headers_input) if custom_headers_input.strip() else {}
                except json.JSONDecodeError:
                    st.error("❌ Invalid JSON in headers. Please check your format.")
                    return
                
                # Store configuration in session state
                st.session_state.test_config = {
                    'api_endpoint': selected_endpoint['url'],
                    'http_method': selected_endpoint['method'],
                    'sample_payload': sample_payload,
                    'custom_headers': custom_headers,
                    'endpoint_details': endpoint_details
                }
                
                # Show configuration readiness
                st.success("✅ Configuration ready for intelligent security testing!")
                
                # Show what will be tested based on analysis
                with st.expander("🎯 Planned Test Coverage Based on Code Analysis", expanded=False):
                    st.write("**The following test categories will be generated based on your code:**")
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write("**🔒 Security Tests:**")
                        if code_analysis.get('authentication_methods'):
                            st.write("• Authentication bypass attempts")
                        if code_analysis.get('database_operations'):
                            st.write("• SQL injection variations")
                        if code_analysis.get('validation_patterns'):
                            st.write("• Input validation bypass")
                        if code_analysis.get('business_logic'):
                            st.write("• Business logic manipulation")
                        
                        st.write("**⚡ Flow & Logic Tests:**")
                        if 'role_based_logic' in code_analysis.get('business_logic', []):
                            st.write("• Role/permission escalation")
                        if 'state_dependent_logic' in code_analysis.get('business_logic', []):
                            st.write("• State transition attacks")
                        if 'workflow_logic' in code_analysis.get('business_logic', []):
                            st.write("• Workflow sequence bypass")
                    
                    with col2:
                        st.write("**📊 Boundary Tests:**")
                        if 'length_validation' in code_analysis.get('validation_patterns', []):
                            st.write("• Field length boundary testing")
                        if 'range_validation' in code_analysis.get('validation_patterns', []):
                            st.write("• Numeric range violations")
                        if 'type_validation' in code_analysis.get('validation_patterns', []):
                            st.write("• Data type confusion")
                        
                        st.write("**🎭 Edge Cases:**")
                        st.write("• Null/empty value handling")
                        st.write("• Unicode & special characters")
                        st.write("• Malformed data structures")
                        if code_analysis.get('file_operations'):
                            st.write("• File upload/download abuse")
    
    # Context-Aware Test Case Generation and Execution
    if st.session_state.test_config and st.session_state.code_analysis:
        config = st.session_state.test_config
        code_analysis = st.session_state.code_analysis
        
        # Show current configuration
        st.header("Security Test Generation")
        
        # Configuration summary
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Endpoint", config['api_endpoint'].split('/')[-1] if config['api_endpoint'] else "Unknown")
        with col2:
            st.metric("Method", config['http_method'])
        with col3:
            payload_count = len(config['sample_payload']) if config['sample_payload'] else 0
            st.metric("Payload Fields", payload_count)
        with col4:
            analysis_areas = len([v for v in code_analysis.values() if v])
            st.metric("Analysis Areas", analysis_areas)
        
        # Test case generation section
        st.subheader("🚀 Generate Context-Aware Security Tests")
        
        
        col1, col2 = st.columns([1, 1])
        
        with col1:
            if st.button("Generate Context-Aware Tests", type="primary", use_container_width=True):
                with st.spinner("🔍 Analyzing code patterns and generating intelligent security tests..."):
                    st.session_state.test_cases = generate_context_aware_test_cases(
                        client, 
                        config['api_endpoint'], 
                        config['http_method'], 
                        config['sample_payload'], 
                        config['custom_headers'],
                        code_analysis,
                        config['endpoint_details']
                    )
        
        with col2:
            if st.session_state.test_cases:
                test_count = len(st.session_state.test_cases)
                st.metric("Generated Tests", test_count)
                
                # Show distribution by risk level
                risk_dist = {}
                for test in st.session_state.test_cases:
                    risk = test.get('risk_level', 'MEDIUM')
                    risk_dist[risk] = risk_dist.get(risk, 0) + 1
                
                if risk_dist:
                    risk_info = " | ".join([f"{risk}: {count}" for risk, count in sorted(risk_dist.items())])
                    st.caption(f"Risk Distribution: {risk_info}")
        
        # Display generated test cases with enhanced information
        if st.session_state.test_cases:
            st.success(f"✅ Successfully generated {len(st.session_state.test_cases)} context-aware test cases!")
            
            # Test categorization by attack vector
            attack_vectors = {}
            for test in st.session_state.test_cases:
                vector = test.get('attack_vector', 'General Testing')
                attack_vectors[vector] = attack_vectors.get(vector, 0) + 1
            
            vector_info = " | ".join([f"{vector}: {count}" for vector, count in sorted(attack_vectors.items())])
            st.info(f"🎯 **Attack Vector Coverage:** {vector_info}")
            
            # Test cases preview with enhanced details
            with st.expander("📋 Context-Aware Test Cases Report", expanded=False):
                for i, test in enumerate(st.session_state.test_cases, 1):
                    st.markdown("---")
                    
                    # Test header with risk indicator
                    risk_emoji = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}.get(test.get('risk_level', 'MEDIUM'), "⚪")
                    st.markdown(f"**Test {i}:** {test.get('name', 'Unnamed Test')} {risk_emoji}")
                    
                    # Main test information
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown(f"**Attack Vector:** `{test.get('attack_vector', 'General')}`")
                        st.markdown(f"**Code Target:** {test.get('code_target', 'General endpoint')}")
                        st.markdown(f"**Risk Level:** {test.get('risk_level', 'MEDIUM')}")
                    
                    with col2:
                        expected = test.get('expected_status_code', 200)
                        got = test.get('actual_status_code', 'Not executed yet')
                        st.markdown(f"**Expected:** {expected} | **Got:** {got}")
                        
                        # Match status with visual indicator
                        if got == 'Not executed yet':
                            st.markdown("**Status:** ⏳ Not tested")
                        elif expected == got:
                            st.markdown("**Status:** ✅ Passed")
                        else:
                            st.markdown("**Status:** ❌ Failed")
                    
                    # Description
                    st.markdown(f"**Description:** {test.get('description', 'No description available')}")
                    
                    # Technical details in expandable section
                    with st.expander(f"🔍 Technical Details - Test {i}", expanded=False):
                        col1, col2 = st.columns(2)
                        with col1:
                            st.markdown(f"**Method:** {test.get('method', 'GET')}")
                            if test.get('payload') and test['payload'] != config['sample_payload']:
                                st.markdown("**Custom Payload:**")
                                st.code(json.dumps(test['payload'], indent=2), language='json')
                        with col2:
                            if test.get('headers') and test['headers'] != config['custom_headers']:
                                st.markdown("**Custom Headers:**")
                                st.code(json.dumps(test['headers'], indent=2), language='json')
        
        # Test execution section
        if st.session_state.test_cases:
            st.header("⚡ Execute Security Tests")
            
            # Pre-execution summary
            test_summary = {
                'total': len(st.session_state.test_cases),
                'critical': len([t for t in st.session_state.test_cases if t.get('risk_level') == 'CRITICAL']),
                'high': len([t for t in st.session_state.test_cases if t.get('risk_level') == 'HIGH']),
                'medium': len([t for t in st.session_state.test_cases if t.get('risk_level') == 'MEDIUM']),
                'low': len([t for t in st.session_state.test_cases if t.get('risk_level') == 'LOW'])
            }
            
            col1, col2, col3, col4, col5 = st.columns(5)
            with col1:
                st.metric("Total Tests", test_summary['total'])
            with col2:
                st.metric("🔴 Critical", test_summary['critical'])
            with col3:
                st.metric("🟠 High", test_summary['high'])
            with col4:
                st.metric("🟡 Medium", test_summary['medium'])
            with col5:
                st.metric("🟢 Low", test_summary['low'])
            
            col1, col2 = st.columns([1, 1])
            
            with col1:
                if st.button("🎯 Execute All Security Tests", type="primary", use_container_width=True):
                    base_headers = {"Content-Type": "application/json", **config['custom_headers']}
                    
                    with st.spinner("🔍 Executing comprehensive security test suite..."):
                        results, stats, attack_vector_stats, risk_level_stats = execute_tests(
                            st.session_state.test_cases, 
                            config['api_endpoint'], 
                            base_headers
                        )
                        st.session_state.test_results = {
                            'results': results,
                            'stats': stats,
                            'attack_vector_stats': attack_vector_stats,
                            'risk_level_stats': risk_level_stats
                        }
            
            # Display results
            if st.session_state.test_results:
                stats = st.session_state.test_results['stats']
                attack_vector_stats = st.session_state.test_results['attack_vector_stats']
                risk_level_stats = st.session_state.test_results['risk_level_stats']
                results = st.session_state.test_results['results']
                
                st.header("📊 Security Test Results")
                
                # Overall metrics
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    st.metric("Total Tests", stats['total'])
                with col2:
                    success_rate = (stats['passed']/stats['total']*100) if stats['total'] > 0 else 0
                    st.metric("Passed", stats['passed'], delta=f"{success_rate:.1f}%")
                with col3:
                    failure_rate = (stats['failed']/stats['total']*100) if stats['total'] > 0 else 0
                    st.metric("Failed", stats['failed'], delta=f"{failure_rate:.1f}%")
                with col4:
                    st.metric("Errors", stats['errors'])
                
                # Risk-based analysis
                st.subheader("🚨 Risk-Based Analysis")
                
                high_risk_failures = [r for r in results if not r.get("status_matches", False) and r.get("risk_level", "").upper() in ["HIGH", "CRITICAL"]]
                if high_risk_failures:
                    st.error(f"🔴 **CRITICAL ALERT**: {len(high_risk_failures)} high-risk security tests failed!")
                    
                    # Show top high-risk failures
                    with st.expander("🔍 High-Risk Failures Detail", expanded=True):
                        for i, failure in enumerate(high_risk_failures[:10], 1):  # Show top 10
                            st.markdown(f"**{i}. {failure['test_name']}** ({failure['risk_level']})")
                            st.markdown(f"   - Attack Vector: {failure['attack_vector']}")
                            st.markdown(f"   - Expected: {failure.get('expected_status', 'N/A')} | Got: {failure.get('actual_status', 'N/A')}")
                            st.markdown(f"   - Description: {failure['description'][:100]}...")
                else:
                    st.success("✅ **Good News**: No high-risk security vulnerabilities detected!")
                
                # Attack vector breakdown
                st.subheader("🎯 Results by Attack Vector")
                
                attack_data = []
                for attack_vector, av_stats in attack_vector_stats.items():
                    success_rate = (av_stats["passed"] / av_stats["total"] * 100) if av_stats["total"] > 0 else 0
                    attack_data.append({
                        "Attack Vector": attack_vector,
                        "Total": av_stats["total"],
                        "Passed": av_stats["passed"],
                        "Failed": av_stats["failed"],
                        "Success Rate": f"{success_rate:.1f}%"
                    })
                
                attack_df = pd.DataFrame(attack_data)
                st.dataframe(attack_df, use_container_width=True)
                
                # Risk level breakdown
                st.subheader("⚠️ Results by Risk Level")
                
                risk_data = []
                for risk_level, risk_stats in risk_level_stats.items():
                    success_rate = (risk_stats["passed"] / risk_stats["total"] * 100) if risk_stats["total"] > 0 else 0
                    risk_emoji = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}.get(risk_level, "⚪")
                    risk_data.append({
                        "Risk Level": f"{risk_emoji} {risk_level}",
                        "Total": risk_stats["total"],
                        "Passed": risk_stats["passed"],
                        "Failed": risk_stats["failed"],
                        "Success Rate": f"{success_rate:.1f}%"
                    })
                
                risk_df = pd.DataFrame(risk_data)
                st.dataframe(risk_df, use_container_width=True)
                
                # Detailed results table
                with st.expander("📋 All Test Results", expanded=False):
                    display_columns = ['test_name', 'attack_vector', 'risk_level', 'expected_status', 'actual_status', 'test_result', 'description']
                    results_df = pd.DataFrame(results)
                    available_columns = [col for col in display_columns if col in results_df.columns]
                    st.dataframe(results_df[available_columns], use_container_width=True)
                
                # Download section
                st.subheader("💾 Download Comprehensive Security Report")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    # Excel download with enhanced sheets
                    excel_buffer = create_excel_download(results, stats, attack_vector_stats, risk_level_stats)
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    
                    st.download_button(
                        label="📊 Download Complete Security Report (Excel)",
                        data=excel_buffer,
                        file_name=f"context_aware_security_test_report_{timestamp}.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        use_container_width=True
                    )
                
                with col2:
                    # JSON download with code analysis
                    json_data = {
                        'test_metadata': {
                            'endpoint': config['api_endpoint'],
                            'method': config['http_method'],
                            'timestamp': timestamp,
                            'test_type': 'context_aware_security_testing'
                        },
                        'code_analysis': code_analysis,
                        'endpoint_details': config['endpoint_details'],
                        'test_summary': stats,
                        'attack_vector_breakdown': attack_vector_stats,
                        'risk_level_breakdown': risk_level_stats,
                        'detailed_results': results
                    }
                    
                    st.download_button(
                        label="📄 Download Results + Analysis (JSON)",
                        data=json.dumps(json_data, indent=2),
                        file_name=f"context_aware_security_analysis_{timestamp}.json",
                        mime="application/json",
                        use_container_width=True
                    )
    
    else:
        # Show enhanced instructions
        st.info("""
        👆 **How to use the Context-Aware API Security Tester:**
        
        **🔥 What Makes This Different:**
        - **Analyzes YOUR actual code** - Not generic test templates
        - **Understands your implementation** - Auth methods, business logic, validation patterns
        - **Targets real vulnerabilities** - Tests based on detected security patterns
        - **Comprehensive coverage** - Flow, boundary, injection, auth, business logic
        
        **📝 Step-by-Step Process:**
        1. **📁 Provide Your API Code:**
           - Paste complete API implementations with business logic
           - Upload multiple files or ZIP archives
           - Include authentication, validation, and database code
        
        2. **🔧 Add Real-World Context:**
           - Actual cURL commands you use for testing
           - Production/staging API URLs
           - Authentication examples (tokens, headers)
           - Expected behaviors and business rules
        
        3. **🧠 Intelligent Analysis:**
           - Deep code analysis identifies security patterns
           - Auto-detects endpoints, methods, and parameters
           - Maps code patterns to attack vectors
        
        4. **🎯 Targeted Test Generation:**
           - Context-aware tests target YOUR specific implementation
           - Focus on detected vulnerabilities and patterns
           - Comprehensive coverage of all security dimensions
        
        5. **⚡ Execute & Report:**
           - Run tests against your live API
           - Risk-based analysis and reporting
           - Downloadable reports with code correlation
        
        **💡 Pro Tips for Maximum Effectiveness:**
        - Include complete function implementations, not just route definitions
        - Add authentication and authorization code for better security testing
        - Provide real cURL commands with actual headers and payloads
        - Test against staging environments first
        """)
    
    # Enhanced sidebar with intelligent analysis information
    with st.sidebar:
        st.header("🧠 Context-Aware Analysis")
        
        # Show analysis status
        if st.session_state.code_analysis:
            code_analysis = st.session_state.code_analysis
            
            st.subheader("🔍 Detected Patterns")
            
            analysis_categories = [
                ("🔐 Authentication", code_analysis.get('authentication_methods', [])),
                ("✅ Validation", code_analysis.get('validation_patterns', [])),
                ("🛡️ Security Controls", code_analysis.get('security_controls', [])),
                ("🧠 Business Logic", code_analysis.get('business_logic', [])),
                ("💾 Database Ops", code_analysis.get('database_operations', [])),
                ("📁 File Operations", code_analysis.get('file_operations', [])),
                ("📥 Input Sources", code_analysis.get('input_sources', [])),
                ("⚠️ Error Handling", code_analysis.get('error_handling', []))
            ]
            
            for category_name, patterns in analysis_categories:
                if patterns:
                    with st.expander(f"{category_name} ({len(patterns)})", expanded=False):
                        for pattern in patterns:
                            st.write(f"• {pattern.replace('_', ' ').title()}")
        
        # Show endpoint analysis
        if st.session_state.parsed_endpoints:
            st.subheader("🎯 Detected Endpoints")
            for i, endpoint in enumerate(st.session_state.parsed_endpoints):
                with st.expander(f"📍 {endpoint['route']} ({endpoint.get('type', 'unknown').title()})", expanded=False):
                    st.write(f"**Methods:** {', '.join(endpoint['methods'])}")
                    st.write(f"**Function:** {endpoint['function_name']}")
                    
                    if endpoint.get('full_url'):
                        st.write(f"**Full URL:** {endpoint['full_url']}")
                    
                    if endpoint.get('expected_fields'):
                        st.write(f"**Expected Fields:** {', '.join(endpoint['expected_fields'])}")
                    
                    if endpoint.get('headers') and endpoint['headers']:
                        st.write("**Context Headers:**")
                        st.json(endpoint['headers'], expanded=False)
                    
                    if endpoint['sample_payload']:
                        st.write("**Sample Payload:**")
                        st.json(endpoint['sample_payload'], expanded=False)
        
        # Show test generation progress
        if st.session_state.test_cases:
            st.subheader("🧪 Generated Test Analysis")
            
            # Test statistics
            test_stats = {
                'total': len(st.session_state.test_cases),
                'attack_vectors': len(set(t.get('attack_vector', 'unknown') for t in st.session_state.test_cases)),
                'risk_levels': {}
            }
            
            for test in st.session_state.test_cases:
                risk = test.get('risk_level', 'MEDIUM')
                test_stats['risk_levels'][risk] = test_stats['risk_levels'].get(risk, 0) + 1
            
            st.metric("Total Tests", test_stats['total'])
            st.metric("Attack Vectors", test_stats['attack_vectors'])
            
            st.write("**Risk Distribution:**")
            for risk, count in sorted(test_stats['risk_levels'].items()):
                emoji = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}.get(risk, "⚪")
                st.write(f"{emoji} **{risk}:** {count}")
        
        # Show execution results
        if st.session_state.test_results:
            st.subheader("📊 Test Results Summary")
            stats = st.session_state.test_results['stats']
            
            success_rate = (stats['passed'] / stats['total'] * 100) if stats['total'] > 0 else 0
            
            if success_rate >= 80:
                st.success(f"✅ {success_rate:.1f}% Success Rate")
            elif success_rate >= 60:
                st.warning(f"⚠️ {success_rate:.1f}% Success Rate")
            else:
                st.error(f"❌ {success_rate:.1f}% Success Rate")
            
            st.write(f"**Passed:** {stats['passed']}")
            st.write(f"**Failed:** {stats['failed']}")
            st.write(f"**Errors:** {stats['errors']}")
            
            # High-risk failure alert
            if 'results' in st.session_state.test_results:
                high_risk_failures = [r for r in st.session_state.test_results['results'] 
                                    if not r.get("status_matches", False) and 
                                    r.get("risk_level", "").upper() in ["HIGH", "CRITICAL"]]
                if high_risk_failures:
                    st.error(f"🚨 {len(high_risk_failures)} High-Risk Failures!")
                else:
                    st.success("✅ No High-Risk Failures")
            
            # Quick actions
            st.subheader("⚡ Quick Actions")
            
            if stats['failed'] > 0:
                st.write("🔍 Review failed tests in main panel")
            
            if stats['errors'] > 0:
                st.write("⚠️ Check error details in results")
            
            st.write("💾 Download comprehensive reports")

if __name__ == "__main__":
    main()


