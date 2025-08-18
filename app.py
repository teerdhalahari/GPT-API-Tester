import json
import time
import requests
import re
from datetime import datetime
from openai import OpenAI
from io import BytesIO
import os
import streamlit as st
from dotenv import load_dotenv

# Load environment variables (optional for local use)
load_dotenv()

st.title("My GPT App")

# Let user enter their API key
user_api_key = st.text_input("Enter your OpenAI API key:", type="password")

if user_api_key:
    client = OpenAI(api_key=user_api_key)
    st.success("API key accepted! You can now use the app.")

    # 👉 Place your OpenAI logic/code here using `client`

else:
    st.warning("Please enter your OpenAI API key to continue.")


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
</style>
""", unsafe_allow_html=True)

def initialize_openai_client():
    """Initialize OpenAI client with API key from .env file"""
    try:
        if not user_api_key:
            return None, "No user_api_key found in .env file"
        
        client = OpenAI(api_key=user_api_key)
        # Test the connection with a simple request
        client.models.list()
        return client, True
    except Exception as e:
        return None, str(e)

def generate_comprehensive_test_cases(client, api_endpoint, http_method, sample_payload, custom_headers):
    """Generate test cases using GPT with plain text format"""
    
    categories = [
        {
            "name": "Flow Level Edge Cases",
            "description": "Test request flow, order of operations, state changes",
            "coverage_areas": [
                "Missing authentication steps", 
                "Wrong sequence of operations", 
                "Incomplete request flows",
                "Session state transitions",
                "Duplicate operations",
                "Operation dependencies",
                "Flow interruption scenarios"
            ]
        },
        {
            "name": "Limits and Boundaries", 
            "description": "Test maximum/minimum values, length limits, numeric boundaries",
            "coverage_areas": [
                "Field length limits (min/max)",
                "Numeric boundary values", 
                "Empty and null inputs",
                "Integer overflow/underflow",
                "String length extremes",
                "Array size limits",
                "Memory constraints",
                "Timeout boundaries"
            ]
        },
        {
            "name": "Special Characters and Unique Inputs",
            "description": "Test unusual characters, Unicode, symbols",
            "coverage_areas": [
                "Unicode characters (various languages)",
                "Special symbols (@#$%^&*)",
                "Control characters",
                "Emoji and extended Unicode",
                "Encoding edge cases",
                "Null bytes and terminators",
                "Whitespace variations",
                "Character escaping scenarios"
            ]
        },
        {
            "name": "Branches and Conditions",
            "description": "Test different logical paths and conditions", 
            "coverage_areas": [
                "Different user roles/permissions",
                "Conditional business logic",
                "Feature flags and toggles",
                "Status-dependent behavior",
                "Multi-path decision trees",
                "Error condition branches",
                "Configuration-dependent paths",
                "Environment-specific conditions"
            ]
        },
        {
            "name": "Escape Characters and Injection",
            "description": "Test escape sequences and injection attempts",
            "coverage_areas": [
                "SQL injection (various techniques)",
                "XSS (stored, reflected, DOM)",
                "Command injection",
                "LDAP injection",
                "XML/XXE injection",
                "Template injection",
                "Path traversal attacks",
                "Script injection variants",
                "NoSQL injection",
                "OS command injection"
            ]
        },
        {
            "name": "Security Edge Cases",
            "description": "Test authentication bypass, authorization issues",
            "coverage_areas": [
                "Authentication bypass techniques",
                "Authorization privilege escalation",
                "Token manipulation (JWT, session)",
                "CSRF attack scenarios",
                "Session fixation/hijacking",
                "Rate limiting bypass",
                "Input validation bypass",
                "Security header bypass",
                "CORS misconfiguration",
                "Insecure direct object references"
            ]
        }
    ]
    
    all_test_cases = []
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    for i, category in enumerate(categories):
        status_text.text(f"Generating {category['name']}...")
        progress_bar.progress((i + 1) / len(categories))
        
        category_tests = generate_category_tests_plain_text(
            client, category, api_endpoint, http_method, sample_payload, custom_headers
        )
        if category_tests:
            all_test_cases.extend(category_tests)
    
    status_text.text(f"✅ Generated {len(all_test_cases)} total test cases")
    return all_test_cases

def generate_category_tests_plain_text(client, category, api_endpoint, http_method, sample_payload, custom_headers):
    """Generate test cases for a specific category"""
    
    system_prompt = f"""You are an expert API security tester. Generate comprehensive test cases for: {category['name']}

Focus on: {category['description']}
Coverage Areas Required: {len(category['coverage_areas'])} areas to cover

COMPREHENSIVE COVERAGE REQUIREMENTS:
You must ensure thorough testing of ALL these areas:
{chr(10).join(f"• {area}" for area in category['coverage_areas'])}

INTELLIGENT TEST GENERATION:
1. DETERMINE OPTIMAL COUNT: Generate however many tests are needed to comprehensively cover ALL coverage areas
2. QUALITY OVER QUANTITY: Each test should be meaningful and target real scenarios
3. NO ARBITRARY LIMITS: Generate enough tests to ensure complete coverage
4. AVOID REDUNDANCY: Don't create similar tests unless they test genuinely different scenarios


OUTPUT FORMAT (use this EXACT format):
TEST_NAME: [descriptive name]
METHOD: {http_method}
PAYLOAD: [test payload]
HEADERS: [any special headers needed]
EXPECTED_STATUS: [expected HTTP status code]
DESCRIPTION: [what this test validates and why it's important]
RISK_LEVEL: [LOW/MEDIUM/HIGH/CRITICAL]
COVERAGE_AREA: [which coverage area this addresses]
---

QUALITY GUIDELINES:
- Each test should target real vulnerabilities or edge cases
- Vary payloads realistically based on: {sample_payload}
- Use appropriate HTTP status codes (200/201 success, 400 bad request, 401 unauthorized, 403 forbidden, 422 validation error, 429 rate limit, 500 server error)
- Ensure every coverage area is addressed by at least one test
- Create additional tests for high-risk areas that warrant multiple test scenarios
"""

    user_prompt = f"""Generate comprehensive test cases for {category['name']} targeting {api_endpoint}

BASE CONFIGURATION:
- Endpoint: {api_endpoint} 
- Method: {http_method}
- Sample payload: {sample_payload}
- Headers: {custom_headers}

COMPREHENSIVE COVERAGE MISSION:
Create enough test cases to thoroughly validate ALL {len(category['coverage_areas'])} coverage areas:
{chr(10).join(f"{i+1}. {area}" for i, area in enumerate(category['coverage_areas']))}

INSTRUCTIONS:
- Analyze each coverage area and determine what tests are needed
- Generate as many tests as required for complete coverage 
- Ensure no coverage area is left untested
- Create multiple tests for complex areas that need various attack vectors
- Focus on realistic scenarios that actual security testers would use
- Each test should provide unique value and not duplicate existing coverage

Your goal is COMPLETE COVERAGE, not hitting a specific number. Generate however many tests are needed to comprehensively test this category.

"""

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.2,  
            max_tokens=6000 
        )
        
        raw_response = response.choices[0].message.content.strip()
        test_cases = parse_plain_text_tests(raw_response, category['name'], sample_payload, custom_headers)
        return test_cases
        
    except Exception as e:
        st.error(f"Failed to generate tests for {category['name']}: {e}")
        return []

def parse_plain_text_tests(raw_text, category, sample_payload, custom_headers):
    """Parse plain text test cases"""
    
    if not raw_text or raw_text.strip() == "":
        return []
    
    test_cases = []
    test_blocks = raw_text.split('---')
    
    for block in test_blocks:
        if not block.strip():
            continue
            
        test_case = {"category": category.lower().replace(' ', '_')}
        
        patterns = {
            'name': r'TEST_NAME:\s*(.+?)(?:\n|$)',
            'method': r'METHOD:\s*(.+?)(?:\n|$)', 
            'payload': r'PAYLOAD:\s*(.+?)(?=\nHEADERS:|\nEXPECTED_STATUS:|\nDESCRIPTION:|$)',
            'headers': r'HEADERS:\s*(.+?)(?=\nEXPECTED_STATUS:|\nDESCRIPTION:|$)',
            'expected_status': r'EXPECTED_STATUS:\s*(.+?)(?:\n|$)',
            'description': r'DESCRIPTION:\s*(.+?)(?=\nRISK_LEVEL:|\nCOVERAGE_AREA:|$)',
            'risk_level': r'RISK_LEVEL:\s*(.+?)(?:\n|$)',
            'coverage_area': r'COVERAGE_AREA:\s*(.+?)(?:\n|$)'  
        }
        
        for field, pattern in patterns.items():
            match = re.search(pattern, block, re.DOTALL | re.IGNORECASE)
            if match:
                value = match.group(1).strip()
                
                if field == 'payload':
                    test_case['payload'] = parse_payload_value(value, sample_payload)
                elif field == 'headers':
                    test_case['headers'] = parse_headers_value(value, custom_headers)
                elif field == 'expected_status':
                    try:
                        test_case['expected_status_code'] = int(re.findall(r'\d+', value)[0])
                    except:
                        test_case['expected_status_code'] = 200
                else:
                    test_case[field] = value
        
        # Only add if we got the essential fields
        if all(key in test_case for key in ['name', 'method', 'expected_status_code']):
            # Set defaults for missing fields
            if 'payload' not in test_case:
                test_case['payload'] = sample_payload
            if 'headers' not in test_case:
                test_case['headers'] = custom_headers
            if 'risk_level' not in test_case:
                test_case['risk_level'] = 'MEDIUM'
            if 'description' not in test_case:
                test_case['description'] = 'Test case validation'
                
            test_cases.append(test_case)
    
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
        
        if func_match:
            func_body = func_match.group(1)
            
            # Look for data.get() calls to identify expected fields
            field_pattern = r'data\.get\(["\']([^"\']+)["\']'
            fields = re.findall(field_pattern, func_body)
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
            'expected_statuses': expected_statuses
        })
    
    return endpoints

def create_endpoint_selector(endpoints, base_url):
    """Create a selector for available endpoints"""
    
    if not endpoints:
        return None, None, None, None
    
    # Create options for selectbox
    options = []
    for endpoint in endpoints:
        for method in endpoint['methods']:
            full_url = f"{base_url.rstrip('/')}{endpoint['route']}"
            options.append({
                'display': f"{method} {endpoint['route']} ({endpoint['function_name']})",
                'url': full_url,
                'method': method,
                'payload': endpoint['sample_payload'],
                'expected_statuses': endpoint['expected_statuses']
            })
    
    return options

def execute_tests(test_cases, api_endpoint, base_headers):
    """Execute all test cases and return results"""
    
    results = []
    stats = {"total": 0, "passed": 0, "failed": 0, "errors": 0}
    category_stats = {}
    
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    for i, test_case in enumerate(test_cases):
        progress_bar.progress((i + 1) / len(test_cases))
        status_text.text(f"Executing test {i+1}/{len(test_cases)}: {test_case['name']}")
        
        category = test_case.get("category", "unknown")
        
        if category not in category_stats:
            category_stats[category] = {"total": 0, "passed": 0, "failed": 0}
        category_stats[category]["total"] += 1
        stats["total"] += 1
        
        try:
            method = test_case.get("method", "GET")
            payload = test_case.get("payload")
            headers = {**base_headers, **(test_case.get("headers", {}) or {})}
            expected_status = test_case.get("expected_status_code", 200)
            risk_level = test_case.get("risk_level", "MEDIUM")
            
            response = make_request(method, api_endpoint, payload, headers)
            
            status_matches = response.status_code == expected_status
            
            if status_matches:
                stats["passed"] += 1
                category_stats[category]["passed"] += 1
            else:
                stats["failed"] += 1
                category_stats[category]["failed"] += 1
            
            results.append({
                "test_name": test_case["name"],
                "category": category,
                "description": test_case.get("description", ""),
                "method": method,
                "payload": str(payload) if payload else "",
                "headers": str(test_case.get("headers", {})),
                "expected_status": expected_status,
                "actual_status": response.status_code,
                "response_body": response.text[:200],
                "response_time": response.elapsed.total_seconds(),
                "status_matches": status_matches,
                "risk_level": risk_level,
                "coverage_area": test_case.get("coverage_area", ""),
                "test_result": "PASS" if status_matches else "FAIL"
            })
            
        except Exception as e:
            stats["errors"] += 1
            category_stats[category]["failed"] += 1
            
            results.append({
                "test_name": test_case["name"],
                "category": category,
                "description": test_case.get("description", ""),
                "error": str(e),
                "status_matches": False,
                "risk_level": test_case.get("risk_level", "MEDIUM"),
                "coverage_area": test_case.get("coverage_area", ""),
                "test_result": "ERROR"
            })
    
    status_text.text("✅ Test execution completed!")
    return results, stats, category_stats

def make_request(method, url, payload=None, headers=None):
    """Make HTTP request"""
    
    request_kwargs = {
        "url": url,
        "headers": headers or {"Content-Type": "application/json"},
        "timeout": 10
    }
    
    if method.upper() in ["POST", "PUT", "PATCH"] and payload is not None:
        if isinstance(payload, dict):
            request_kwargs["json"] = payload
        else:
            request_kwargs["data"] = str(payload)
    elif method.upper() == "GET" and payload:
        request_kwargs["params"] = payload if isinstance(payload, dict) else {"q": str(payload)}
    
    return requests.request(method, **request_kwargs)

def create_excel_download(results, stats, category_stats):
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
        
        # Category breakdown sheet
        category_data = []
        for category, cat_stats in category_stats.items():
            category_data.append({
                "Category": category.replace('_', ' ').title(),
                "Total Tests": cat_stats["total"],
                "Passed": cat_stats["passed"],
                "Failed": cat_stats["failed"],
                "Success Rate (%)": round((cat_stats["passed"] / cat_stats["total"] * 100) if cat_stats["total"] > 0 else 0, 2)
            })
        category_df = pd.DataFrame(category_data)
        category_df.to_excel(writer, sheet_name='Category Breakdown', index=False)
        
        # Detailed results sheet
        results_df = pd.DataFrame(results)
        results_df.to_excel(writer, sheet_name='Detailed Results', index=False)
        
        # Failed tests only sheet
        failed_tests = [r for r in results if not r.get("status_matches", False)]
        if failed_tests:
            failed_df = pd.DataFrame(failed_tests)
            failed_df.to_excel(writer, sheet_name='Failed Tests', index=False)
    
    buffer.seek(0)
    return buffer

# Main Streamlit App
def main():
    st.markdown('<div class="main-header">🔒 GPT API Security Tester</div>', unsafe_allow_html=True)
    
    # Initialize OpenAI client
    client, error = initialize_openai_client()
    if not client:
        st.error(f"❌ OpenAI API connection failed: {error}")
        st.info("💡 Please make sure you have a `.env` file in your project directory with: `user_api_key=your_api_key_here`")
        return
    else:
        st.success("✅ OpenAI API connected successfully!")
    
    # Main content area - Flask Code Input
    st.header("📝 Flask API Code Analysis")
    
    # Code input section
    flask_code = st.text_area(
        "Paste your Flask API code here:",
        height=300,
        placeholder="""# Example:
from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route("/login", methods=["POST"])
def login():
    data = request.json or {}
    username = data.get("username")
    password = data.get("password")
    # ... rest of your code
""",
        help="Paste your complete Flask API code. The app will automatically detect endpoints and methods."
    )
    
    # Base URL input
    col1, col2 = st.columns([2, 1])
    with col1:
        base_url = st.text_input(
            "Base URL for your API:",
            value="http://localhost:5000",
            help="Enter the base URL where your Flask API is running"
        )
    
    with col2:
        analyze_button = st.button("🔍 Analyze Code", type="primary", use_container_width=True)
    
    # Initialize session state for parsed endpoints
    if 'parsed_endpoints' not in st.session_state:
        st.session_state.parsed_endpoints = None
    
    # Analyze Flask code
    if analyze_button and flask_code.strip():
        with st.spinner("Analyzing Flask API code..."):
            endpoints = parse_flask_code(flask_code)
            st.session_state.parsed_endpoints = endpoints
            
            if endpoints:
                st.success(f"✅ Found {len(endpoints)} endpoint(s)!")
            else:
                st.error("❌ No Flask routes found. Please check your code format.")
    
    # Display parsed endpoints and configuration
    if st.session_state.parsed_endpoints:
        endpoints = st.session_state.parsed_endpoints
        
        # Create endpoint options
        endpoint_options = create_endpoint_selector(endpoints, base_url)
        
        if endpoint_options:
            st.header("🎯 Endpoint Selection & Configuration")
            
            # Endpoint selector
            selected_option = st.selectbox(
                "Select an endpoint to test:",
                options=range(len(endpoint_options)),
                format_func=lambda x: endpoint_options[x]['display'],
                help="Choose which endpoint you want to security test"
            )
            
            if selected_option is not None:
                selected_endpoint = endpoint_options[selected_option]
                
                # Display selected endpoint details
                col1, col2 = st.columns(2)
                
                with col1:
                    st.subheader("📋 Endpoint Details")
                    st.write(f"**URL:** `{selected_endpoint['url']}`")
                    st.write(f"**Method:** `{selected_endpoint['method']}`")
                    st.write(f"**Expected Status Codes:** {selected_endpoint['expected_statuses']}")
                
                with col2:
                    st.subheader("📄 Auto-detected Sample Payload")
                    if selected_endpoint['payload']:
                        st.json(selected_endpoint['payload'])
                    else:
                        st.info("No payload detected (likely GET endpoint)")
                
                # Configuration section
                st.subheader("⚙️ Test Configuration")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    # Allow manual payload editing
                    manual_payload = st.text_area(
                        "Edit Sample Payload (JSON):",
                        value=json.dumps(selected_endpoint['payload'], indent=2) if selected_endpoint['payload'] else "{}",
                        help="Modify the auto-detected payload or add your own"
                    )
                
                with col2:
                    # Custom headers
                    custom_headers_input = st.text_area(
                        "Custom Headers (JSON):",
                        value='{"Content-Type": "application/json"}',
                        help="Add any custom headers needed for authentication, etc."
                    )
                
                # Parse the inputs
                try:
                    sample_payload = json.loads(manual_payload) if manual_payload.strip() else {}
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
                    'custom_headers': custom_headers
                }
                
                # Initialize test-related session state
                if 'test_cases' not in st.session_state:
                    st.session_state.test_cases = None
                if 'test_results' not in st.session_state:
                    st.session_state.test_results = None
                
                # Test case generation section
                st.header("🧪 Test Case Generation")
                
                col1, col2 = st.columns([1, 1])
                
                with col1:
                    if st.button("🚀 Generate Test Cases", type="primary", use_container_width=True):
                        config = st.session_state.test_config
                        with st.spinner("Generating comprehensive test cases..."):
                            st.session_state.test_cases = generate_comprehensive_test_cases(
                                client, 
                                config['api_endpoint'], 
                                config['http_method'], 
                                config['sample_payload'], 
                                config['custom_headers']
                            )
                
                with col2:
                    if st.session_state.test_cases:
                        st.metric("Generated Test Cases", len(st.session_state.test_cases))
                
                # Display generated test cases
                if st.session_state.test_cases:
                    st.success(f"✅ Successfully generated {len(st.session_state.test_cases)} test cases!")
                    categories = {}
                    for test in st.session_state.test_cases:
                        category = test.get('category', 'unknown')
                        categories[category] = categories.get(category, 0) + 1
                    category_info = " | ".join([f"{cat.replace('_', ' ').title()}: {count}" for cat, count in categories.items()])
                    st.info(f"📊 **Category Breakdown:** {category_info}")
                    
                    # Test cases preview
                    with st.expander("📋 Detailed Test Cases Report", expanded=False):
                        for i, test in enumerate(st.session_state.test_cases, 1):
                            st.markdown("---")  # Separator line
                            
                            # Test details in your requested format
                            st.markdown(f"**Test:** {test.get('name', 'Unnamed Test')}")
                            st.markdown(f"**Category:** `{test.get('category', 'unknown')}`")
                            st.markdown(f"**Coverage Area:** {test.get('coverage_area', 'General testing')}")
                            
                            # Expected vs Got format
                            expected = test.get('expected_status_code', 200)
                            got = test.get('actual_status_code', 'Not executed yet')
                            
                            st.markdown(f"**Expected:** {expected} | **Got:** {got}")
                            
                            # Match status with visual indicator
                            if got == 'Not executed yet':
                                st.markdown("**Match:** ⏳ Not tested")
                            elif expected == got:
                                st.markdown("**Match:** ✅ True")
                            else:
                                st.markdown("**Match:** ❌ False")
                            
                            # Description
                            st.markdown(f"**Description:** {test.get('description', 'No description available')}")
                            
                            # Additional details in expandable section
                            with st.expander(f"🔍 Technical Details - Test {i}", expanded=False):
                                col1, col2 = st.columns(2)
                                with col1:
                                    st.markdown(f"**Method:** {test.get('method', 'GET')}")
                                    st.markdown(f"**Risk Level:** {test.get('risk_level', 'MEDIUM')}")
                                with col2:
                                    if test.get('payload'):
                                        st.markdown("**Payload:**")
                                        st.code(json.dumps(test['payload'], indent=2), language='json')
                                    if test.get('headers'):
                                        st.markdown("**Headers:**")
                                        st.code(json.dumps(test['headers'], indent=2), language='json')
                
                # Test execution section
                if st.session_state.test_cases:
                    st.header("⚡ Test Execution")
                    
                    col1, col2 = st.columns([1, 1])
                    
                    with col1:
                        if st.button("🎯 Execute Tests", type="primary", use_container_width=True):
                            config = st.session_state.test_config
                            base_headers = {"Content-Type": "application/json", **config['custom_headers']}
                            
                            with st.spinner("Executing tests..."):
                                results, stats, category_stats = execute_tests(
                                    st.session_state.test_cases, 
                                    config['api_endpoint'], 
                                    base_headers
                                )
                                st.session_state.test_results = {
                                    'results': results,
                                    'stats': stats,
                                    'category_stats': category_stats
                                }
                    
                    # Display results
                    if st.session_state.test_results:
                        stats = st.session_state.test_results['stats']
                        category_stats = st.session_state.test_results['category_stats']
                        results = st.session_state.test_results['results']
                        
                        st.header("📊 Test Results")
                        
                        # Overall metrics
                        col1, col2, col3, col4 = st.columns(4)
                        
                        with col1:
                            st.metric("Total Tests", stats['total'])
                        with col2:
                            st.metric("Passed", stats['passed'], delta=f"{stats['passed']/stats['total']*100:.1f}%")
                        with col3:
                            st.metric("Failed", stats['failed'], delta=f"{stats['failed']/stats['total']*100:.1f}%")
                        with col4:
                            st.metric("Errors", stats['errors'])
                        
                        # Category breakdown
                        st.subheader("📂 Results by Category")
                        
                        category_data = []
                        for category, cat_stats in category_stats.items():
                            success_rate = (cat_stats["passed"] / cat_stats["total"] * 100) if cat_stats["total"] > 0 else 0
                            category_data.append({
                                "Category": category.replace('_', ' ').title(),
                                "Total": cat_stats["total"],
                                "Passed": cat_stats["passed"],
                                "Failed": cat_stats["failed"],
                                "Success Rate": f"{success_rate:.1f}%"
                            })
                        
                        category_df = pd.DataFrame(category_data)
                        st.dataframe(category_df, use_container_width=True)
                        
                        # Failed tests summary
                        failed_tests = [r for r in results if not r.get("status_matches", False)]
                        if failed_tests:
                            st.subheader("❌ Failed Tests Summary")
                            
                            high_risk_failures = [r for r in failed_tests if r.get("risk_level", "").upper() in ["HIGH", "CRITICAL"]]
                            if high_risk_failures:
                                st.error(f"🚨 {len(high_risk_failures)} high-risk failures detected!")
                            
                            # Show failed tests table
                            failed_df = pd.DataFrame(failed_tests)
                            display_columns = ['test_name', 'category', 'expected_status', 'actual_status', 'risk_level', 'test_result']
                            available_columns = [col for col in display_columns if col in failed_df.columns]
                            st.dataframe(failed_df[available_columns], use_container_width=True)
                        
                        # Download section
                        st.subheader("💾 Download Results")
                        
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            # Excel download
                            excel_buffer = create_excel_download(results, stats, category_stats)
                            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                            
                            st.download_button(
                                label="📊 Download Detailed Report (Excel)",
                                data=excel_buffer,
                                file_name=f"api_test_results_{timestamp}.xlsx",
                                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                use_container_width=True
                            )
                        
                        with col2:
                            # JSON download
                            config = st.session_state.test_config
                            json_data = {
                                'summary': stats,
                                'category_breakdown': category_stats,
                                'detailed_results': results,
                                'timestamp': timestamp,
                                'endpoint': config['api_endpoint'],
                                'method': config['http_method']
                            }
                            
                            st.download_button(
                                label="📄 Download Results (JSON)",
                                data=json.dumps(json_data, indent=2),
                                file_name=f"api_test_results_{timestamp}.json",
                                mime="application/json",
                                use_container_width=True
                            )
    
    else:
        # Show instructions if no code is provided
        st.info("""
        👆 **How to use:**
        
        1. **Paste your Flask API code** in the text area above
        2. **Set your base URL** (e.g., http://localhost:5000)  
        3. **Click 'Analyze Code'** to detect endpoints automatically
        4. **Select an endpoint** to test from the dropdown
        5. **Generate and execute** comprehensive security tests
        6. **Download detailed results** in Excel format
        
        The app will automatically detect:
        - 🎯 All Flask routes and HTTP methods
        - 📝 Expected request payloads 
        - 📊 Expected response status codes
        - 🔒 Security test scenarios
        """)
    
    # Sidebar with detected endpoints info
    if st.session_state.parsed_endpoints:
        with st.sidebar:
            st.header("🔍 Detected Endpoints")
            for i, endpoint in enumerate(st.session_state.parsed_endpoints):
                with st.expander(f"📍 {endpoint['route']}", expanded=False):
                    st.write(f"**Methods:** {', '.join(endpoint['methods'])}")
                    st.write(f"**Function:** {endpoint['function_name']}")
                    if endpoint['expected_fields']:
                        st.write(f"**Expected Fields:** {', '.join(endpoint['expected_fields'])}")
                    if endpoint['sample_payload']:
                        st.write("**Sample Payload:**")
                        st.json(endpoint['sample_payload'], expanded=False)

if __name__ == "__main__":

    main()

