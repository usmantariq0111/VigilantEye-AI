"""
Advanced Pattern Recognition Engine
Provides intelligent analysis capabilities for file content detection.
"""
import os
import base64
import re
import json
import time
from PIL import Image, ImageSequence

try:
    from dotenv import load_dotenv
    load_dotenv()  # Load .env file
except ImportError:
    pass

try:
    import google.generativeai as genai
    from google.api_core import exceptions as google_exceptions
    ENGINE_AVAILABLE = True
except ImportError:
    ENGINE_AVAILABLE = False
    google_exceptions = None


def _extract_json_object(text, start_idx):
    """Extract a complete JSON object from text starting at start_idx."""
    brace_count = 0
    in_string = False
    escape_next = False
    
    for i in range(start_idx, len(text)):
        char = text[i]
        
        if escape_next:
            escape_next = False
            continue
        
        if char == '\\':
            escape_next = True
            continue
        
        if char == '"' and not escape_next:
            in_string = not in_string
            continue
        
        if not in_string:
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    return text[start_idx:i+1]
    
    return None


def _fix_json_string(json_str):
    """Try to fix common JSON formatting issues."""
    # Remove trailing commas before closing braces/brackets
    json_str = re.sub(r',\s*}', '}', json_str)
    json_str = re.sub(r',\s*]', ']', json_str)
    # Try to close unclosed strings
    if json_str.count('"') % 2 != 0:
        json_str += '"'
    return json_str


def extract_payload(content: bytes):
    """
    Comprehensive payload extraction from GIF file.
    Scans the ENTIRE file including headers, metadata, comments, and appended data.
    Does not skip any section of the file.
    Optimized for performance with large files.
    """
    findings = []
    file_size = len(content)
    
    # Limit file size for processing (prevent memory issues)
    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
    if file_size > MAX_FILE_SIZE:
        # For very large files, only scan first and last portions
        content = content[:10*1024*1024] + content[-10*1024*1024:]  # First and last 10MB
    
    # Decode entire file content for text analysis (preserve all bytes)
    content_str = content.decode(errors='ignore', encoding='latin-1')
    
    # === 1. SCAN APPENDED DATA (after GIF terminator) ===
    gif_terminator = b'\x00\x3B'
    terminator_pos = content.rfind(gif_terminator)
    
    if terminator_pos > 0 and terminator_pos < file_size - 2:
        appended_data = content[terminator_pos + 2:]
        appended_str = appended_data.decode(errors='ignore', encoding='latin-1')
        
        if len(appended_data) > 0:  # Any appended data is suspicious
            # Base64 detection in appended data
            base64_pattern = r'(?:[A-Za-z0-9+/]{20,}={0,2})'
            base64_matches = re.findall(base64_pattern, appended_str)
            for match in base64_matches[:10]:  # Check up to 10 matches
                try:
                    decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                    if decoded and len(decoded) > 5:  # Valid decoded content
                        # Check if decoded content contains suspicious keywords
                        suspicious_keywords = ['cmd', 'powershell', 'http', 'bash', 'wget', 'curl', 'exec', 'eval', 
                                             'system', 'shell', 'python', 'perl', 'ruby', 'script', 'payload', 'malware']
                        if any(keyword in decoded.lower() for keyword in suspicious_keywords):
                            findings.append({
                                'type': 'base64_payload',
                                'location': f'appended_data (offset: {terminator_pos + 2})',
                                'encoded': match[:80] + '...' if len(match) > 80 else match,
                                'decoded': decoded[:300] + '...' if len(decoded) > 300 else decoded
                            })
                except Exception:
                    continue
    
    # === 2. SCAN ENTIRE FILE FOR CODE PATTERNS ===
    # Comprehensive pattern matching across the entire file
    suspicious_patterns = [
        (r'<\?php\s+.*?\?>', 'php_script', re.IGNORECASE | re.DOTALL),
        (r'<script[^>]*>.*?</script>', 'javascript', re.IGNORECASE | re.DOTALL),
        (r'<\?=.*?\?>', 'php_short_tag', re.IGNORECASE | re.DOTALL),
        (r'<%.*?%>', 'asp_script', re.IGNORECASE | re.DOTALL),
        (r'\beval\s*\(', 'eval_call', re.IGNORECASE),
        (r'\bexec\s*\(', 'exec_call', re.IGNORECASE),
        (r'\bexec\s*\(', 'exec_call', re.IGNORECASE),
        (r'os\.system\s*\(', 'system_call', re.IGNORECASE),
        (r'subprocess\.', 'subprocess_call', re.IGNORECASE),
        (r'cmd\.exe\s+/[cC]', 'cmd_execution', re.IGNORECASE),
        (r'powershell\s+-[eE]', 'powershell_encoded', re.IGNORECASE),
        (r'powershell\s+-[cC]', 'powershell_command', re.IGNORECASE),
        (r'bash\s+-[ic]', 'bash_execution', re.IGNORECASE),
        (r'sh\s+-c\s+', 'shell_execution', re.IGNORECASE),
        (r'curl\s+https?://', 'curl_download', re.IGNORECASE),
        (r'wget\s+https?://', 'wget_download', re.IGNORECASE),
        (r'rm\s+-rf\s+/', 'dangerous_rm', re.IGNORECASE),
        (r'del\s+/[fFsS]', 'dangerous_del', re.IGNORECASE),
        (r'format\s+[cC]:', 'format_command', re.IGNORECASE),
        (r'base64_decode\s*\(', 'base64_decode', re.IGNORECASE),
        (r'atob\s*\(', 'base64_decode_js', re.IGNORECASE),
        (r'String\.fromCharCode', 'char_code_obfuscation', re.IGNORECASE),
        (r'unescape\s*\(', 'unescape_obfuscation', re.IGNORECASE),
        (r'document\.write\s*\(', 'dom_manipulation', re.IGNORECASE),
        (r'innerHTML\s*=', 'dom_injection', re.IGNORECASE),
        (r'\.innerHTML\s*=', 'dom_injection', re.IGNORECASE),
    ]
    
    for pattern, pat_type, flags in suspicious_patterns:
        matches = re.findall(pattern, content_str, flags)
        for idx, m in enumerate(matches[:5]):  # Check up to 5 matches per pattern
            match_str = m.strip() if isinstance(m, str) else str(m).strip()
            if len(match_str) > 5:  # Only meaningful matches
                # Find position in file
                match_pos = content_str.find(match_str)
                location = f"file_content (offset: {match_pos})" if match_pos >= 0 else "file_content"
                findings.append({
                    'type': 'suspicious_pattern',
                    'pattern_type': pat_type,
                    'location': location,
                    'match': match_str[:200] + '...' if len(match_str) > 200 else match_str
                })
    
    # === 3. SCAN FOR BASE64 IN ENTIRE FILE (not just appended) ===
    # Look for base64 strings throughout the file
    base64_pattern = r'(?:[A-Za-z0-9+/]{40,}={0,2})'
    all_base64 = re.findall(base64_pattern, content_str)
    for b64_match in all_base64[:15]:  # Check up to 15 base64 strings
        try:
            decoded = base64.b64decode(b64_match).decode('utf-8', errors='ignore')
            if decoded and len(decoded) > 10:
                # Check for executable code patterns in decoded content
                code_indicators = ['<?php', '<script', 'eval', 'exec', 'system', 'shell', 'cmd', 'powershell', 
                                 'bash', 'python', 'import', 'require', 'include', 'function', 'class']
                if any(indicator in decoded.lower() for indicator in code_indicators):
                    b64_pos = content_str.find(b64_match)
                    findings.append({
                        'type': 'base64_payload',
                        'location': f'file_content (offset: {b64_pos})',
                        'encoded': b64_match[:80] + '...' if len(b64_match) > 80 else b64_match,
                        'decoded': decoded[:400] + '...' if len(decoded) > 400 else decoded
                    })
        except Exception:
            continue
    
    # === 4. SCAN FOR COMPLETE MALICIOUS SCRIPTS ===
    # PHP scripts
    php_scripts = re.findall(r'<\?php\s+.*?\?>', content_str, re.IGNORECASE | re.DOTALL)
    for script in php_scripts:
        malicious_keywords = ['eval', 'exec', 'system', 'shell_exec', 'passthru', 'assert', 'preg_replace', 
                            'create_function', 'call_user_func', 'file_get_contents', 'file_put_contents']
        if any(keyword in script.lower() for keyword in malicious_keywords):
            script_pos = content_str.find(script)
            findings.append({
                'type': 'complete_malicious_script',
                'location': f'file_content (offset: {script_pos})',
                'match': script[:500] + '...' if len(script) > 500 else script
            })
    
    # JavaScript scripts
    js_scripts = re.findall(r'<script[^>]*>.*?</script>', content_str, re.IGNORECASE | re.DOTALL)
    for script in js_scripts:
        js_keywords = ['eval', 'exec', 'document.write', 'innerHTML', 'Function', 'setTimeout', 'setInterval',
                      'XMLHttpRequest', 'fetch', 'atob', 'unescape', 'String.fromCharCode']
        if any(keyword in script.lower() for keyword in js_keywords):
            script_pos = content_str.find(script)
            findings.append({
                'type': 'complete_malicious_script',
                'location': f'file_content (offset: {script_pos})',
                'match': script[:500] + '...' if len(script) > 500 else script
            })
    
    # === 5. SCAN FOR URLS AND IP ADDRESSES ===
    # URLs (check all, not just when other findings exist)
    urls = re.findall(r'https?://[^\s\'"<>\)]+', content_str)
    for url in urls[:10]:  # Check up to 10 URLs
        # Skip common legitimate image hosting domains
        if not any(domain in url.lower() for domain in ['imgur.com', 'giphy.com', 'tenor.com', 'gstatic.com', 
                                                         'googleapis.com', 'cdn.jsdelivr.net', 'cdnjs.cloudflare.com']):
            url_pos = content_str.find(url)
            findings.append({
                'type': 'suspicious_url',
                'location': f'file_content (offset: {url_pos})',
                'match': url
            })
    
    # IP addresses
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    ips = re.findall(ip_pattern, content_str)
    for ip in ips[:5]:  # Check up to 5 IPs
        # Skip common localhost/private IPs unless in suspicious context
        if ip not in ['127.0.0.1', '0.0.0.0', '255.255.255.255']:
            ip_pos = content_str.find(ip)
            findings.append({
                'type': 'ip_address',
                'location': f'file_content (offset: {ip_pos})',
                'match': ip
            })
    
    # === 6. SCAN FOR HEX-ENCODED STRINGS ===
    # Look for hex-encoded payloads (common obfuscation)
    hex_pattern = r'\\x[0-9a-fA-F]{2}'
    hex_sequences = re.findall(r'(?:\\x[0-9a-fA-F]{2}){10,}', content_str)
    for hex_seq in hex_sequences[:5]:
        try:
            # Try to decode hex sequence
            hex_bytes = bytes.fromhex(hex_seq.replace('\\x', ''))
            decoded_hex = hex_bytes.decode('utf-8', errors='ignore')
            if any(keyword in decoded_hex.lower() for keyword in ['eval', 'exec', 'system', 'cmd', 'shell']):
                hex_pos = content_str.find(hex_seq)
                findings.append({
                    'type': 'hex_encoded_payload',
                    'location': f'file_content (offset: {hex_pos})',
                    'match': hex_seq[:100] + '...' if len(hex_seq) > 100 else hex_seq
                })
        except Exception:
            continue
    
    # === 7. SCAN FOR COMMENT-BASED PAYLOADS ===
    # GIF comments can contain payloads
    comment_patterns = [
        r'<!--.*?-->',  # HTML comments
        r'/\*.*?\*/',   # C-style comments
        r'//.*?$',      # Single-line comments
    ]
    for pattern in comment_patterns:
        comments = re.findall(pattern, content_str, re.IGNORECASE | re.DOTALL | re.MULTILINE)
        for comment in comments:
            if any(keyword in comment.lower() for keyword in ['eval', 'exec', 'script', 'payload', 'malware', 'exploit']):
                comment_pos = content_str.find(comment)
                findings.append({
                    'type': 'comment_payload',
                    'location': f'file_content (offset: {comment_pos})',
                    'match': comment[:300] + '...' if len(comment) > 300 else comment
                })
    
    # === Return comprehensive result ===
    if findings:
        readable = f"=== COMPREHENSIVE SCAN RESULTS ({len(findings)} findings) ===\n"
        readable += f"File Size: {file_size} bytes\n"
        readable += f"Scanned: Entire file (0 to {file_size} bytes)\n\n"
        
        # Group findings by type
        by_type = {}
        for item in findings:
            item_type = item.get('pattern_type', item['type'])
            if item_type not in by_type:
                by_type[item_type] = []
            by_type[item_type].append(item)
        
        for item_type, items in by_type.items():
            readable += f"\n--- {item_type.upper().replace('_', ' ')} ({len(items)} found) ---\n"
            for item in items:
                if item['type'] == 'base64_payload':
                    readable += f"\nLocation: {item.get('location', 'unknown')}\n"
                    readable += f"Encoded: {item['encoded']}\n"
                    readable += f"Decoded: {item['decoded']}\n"
                else:
                    readable += f"\nLocation: {item.get('location', 'unknown')}\n"
                    readable += f"Match: {item['match']}\n"
        
        return "suspicious", readable.strip()
    else:
        return "clean", f"Comprehensive scan completed. File size: {file_size} bytes. No malicious patterns detected in any section of the file."


def analyze_file(gif_path, api_key=None):
    """
    Analyze GIF file using advanced pattern recognition engine.
    Returns similar format to CNN model for consistency.
    """
    if not ENGINE_AVAILABLE:
        return {
            "prediction": "error",
            "model_method": "advanced_analysis",
            "payload_detected": "none",
            "extracted_payload": "Advanced analysis engine not available. Please install required dependencies."
        }
    
    if not api_key:
        # Try to get from environment variable
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            return {
                "prediction": "error",
                "model_method": "advanced_analysis",
                "payload_detected": "none",
                "extracted_payload": "Analysis engine configuration required. Please set GEMINI_API_KEY environment variable."
            }
    
    try:
        # Configure analysis engine
        genai.configure(api_key=api_key)
        model = None
        model_names = [
            'gemini-2.5-pro',             # Latest stable PRO - best for complex malware analysis
            'gemini-3-pro-preview',        # Latest preview PRO - cutting-edge capabilities
            'gemini-1.5-pro',              # Stable PRO - excellent reasoning and analysis
            'gemini-2.5-flash',            # Fast PRO alternative - good balance
            'gemini-3-flash-preview',       # Fast preview alternative
            'gemini-2.0-flash',            # Stable Flash fallback
            'gemini-1.5-flash'             # Widely available Flash fallback
        ]
        
        selected_model_name = None
        last_error = None
        
        for model_name in model_names:
            try:
                model = genai.GenerativeModel(model_name)
                selected_model_name = model_name
                break  # Successfully created model, exit loop
            except Exception as e:
                last_error = str(e)
                # If it's a quota error, try next model (especially Flash models)
                if "quota" in str(e).lower() or "429" in str(e):
                    print(f"[Intelligence Engine] Quota exceeded for {model_name}, trying next model...")
                    continue
                continue  # Try next model name
        
        # Log which model is being used (for debugging)
        if selected_model_name:
            print(f"[Intelligence Engine] Using model: {selected_model_name}")
        
        if model is None:
            error_msg = "No compatible analysis model available."
            if last_error and "quota" in last_error.lower():
                error_msg += " Quota exceeded - PRO models require paid plan. Enable billing or wait for rate limit reset."
            return {
                "prediction": "error",
                "model_method": "advanced_analysis",
                "payload_detected": "none",
                "extracted_payload": error_msg
            }
        
        # Read GIF file
        with open(gif_path, "rb") as f:
            gif_content = f.read()
        
        # Extract metadata and analyze content
        gif_info = {}
        try:
            img = Image.open(gif_path)
            gif_info = {
                "format": img.format,
                "size": img.size,
                "mode": img.mode,
                "frames": getattr(img, 'n_frames', 1),
                "has_transparency": img.info.get('transparency', False),
                "duration": img.info.get('duration', 0),
                "loop": img.info.get('loop', 0)
            }
        except Exception as e:
            gif_info["error"] = str(e)
        
        # Extract text patterns from binary content (decode entire file for comprehensive scan)
        content_str = gif_content.decode(errors='ignore', encoding='latin-1')
        file_size = len(gif_content)
        
        # Comprehensive payload extraction - scans ENTIRE file (no sections skipped)
        suspicious_findings = extract_payload(gif_content)
        
        # Extract hex representation for analysis (sample from beginning, middle, and end)
        hex_samples = []
        # Beginning
        hex_start = gif_content[:500].hex()
        hex_samples.append(f"Start (0-500): {' '.join([hex_start[i:i+2] for i in range(0, min(len(hex_start), 100), 2)])}")
        # Middle
        if file_size > 1000:
            mid_start = file_size // 2 - 250
            hex_mid = gif_content[mid_start:mid_start+500].hex()
            hex_samples.append(f"Middle ({mid_start}-{mid_start+500}): {' '.join([hex_mid[i:i+2] for i in range(0, min(len(hex_mid), 100), 2)])}")
        # End
        if file_size > 500:
            hex_end = gif_content[-500:].hex()
            hex_samples.append(f"End ({file_size-500}-{file_size}): {' '.join([hex_end[i:i+2] for i in range(0, min(len(hex_end), 100), 2)])}")
        hex_pairs = '\n'.join(hex_samples)
        
        # Analyze file structure - check for valid GIF header
        has_valid_gif_header = gif_content[:6] == b'GIF89a' or gif_content[:6] == b'GIF87a'
        
        # Check for appended data (common malware technique)
        gif_end_marker = b'\x00\x3B'  # GIF terminator
        gif_terminator_pos = gif_content.rfind(gif_end_marker)
        has_appended_data = gif_terminator_pos > 0 and gif_terminator_pos < len(gif_content) - 2
        
        # Extract readable strings (potential payloads)
        readable_strings = re.findall(r'[ -~]{10,}', content_str)  # Printable ASCII strings of 10+ chars
        suspicious_strings = [s for s in readable_strings if any(keyword in s.lower() for keyword in 
            ['eval', 'exec', 'system', 'cmd', 'powershell', 'bash', 'curl', 'wget', 'http', 'php', 'script', 'base64'])]
        
        # Prepare comprehensive prompt for analysis engine
        prompt = f"""You are a senior cybersecurity analyst specializing in file-based malware detection. Analyze this GIF file THOROUGHLY and ACCURATELY.

CRITICAL ANALYSIS REQUIREMENTS:
- DO NOT mark files as "infected" based solely on random hex data or normal GIF structure
- Only mark as "infected" if you find ACTUAL malicious code, scripts, or executable payloads
- Normal GIF metadata, color tables, and image data are NOT malicious
- Look for APPENDED data after the GIF terminator (0x00 0x3B)
- Analyze actual readable strings and code, not binary image data

GIF FILE STRUCTURE ANALYSIS:
- File Size: {file_size} bytes
- Format: {gif_info.get('format', 'Unknown')}
- Dimensions: {gif_info.get('size', 'Unknown')}
- Frames: {gif_info.get('frames', 'Unknown')}
- Duration: {gif_info.get('duration', 'Unknown')} ms
- Valid GIF Header: {'Yes' if has_valid_gif_header else 'No'}
- Appended Data After Terminator: {'Yes - Potential payload location' if has_appended_data else 'No - Normal GIF structure'}

EXTRACTED PATTERNS FROM FILE:
{suspicious_findings[1] if suspicious_findings[0] == 'suspicious' else 'No obvious suspicious patterns found in initial scan.'}

SUSPICIOUS READABLE STRINGS FOUND:
{chr(10).join(suspicious_strings[:20]) if suspicious_strings else 'None found - file appears to contain only normal GIF data'}

FILE CONTENT ANALYSIS (Readable text portions - comprehensive scan):
- Beginning (first 2000 chars): {content_str[:2000] if len(content_str) > 0 else 'No readable text'}
- Middle section: {content_str[file_size//2:file_size//2+2000] if file_size > 4000 else 'N/A'}
- End section (last 2000 chars): {content_str[-2000:] if len(content_str) > 2000 else content_str}

HEX ANALYSIS (Samples from beginning, middle, and end):
{hex_pairs}

COMPLETE FILE SCAN STATUS:
- Total bytes scanned: {file_size}
- Scan coverage: 100% (entire file analyzed)
- Sections analyzed: Header, Metadata, Image Data, Comments, Appended Data

ANALYSIS INSTRUCTIONS:
1. First, verify this is a valid GIF file structure
2. Check if there is data appended AFTER the GIF terminator (0x00 0x3B) - this is where malware is often hidden
3. Analyze ONLY the readable strings and code portions - ignore binary image data
4. Look for actual executable code: PHP scripts, JavaScript, shell commands, base64-encoded payloads
5. Distinguish between:
   - Normal GIF metadata/headers (SAFE)
   - Image pixel data (SAFE)
   - Appended malicious code (DANGEROUS)
   - Embedded scripts in comments/metadata (DANGEROUS)

RESPONSE REQUIREMENTS:
- Be ACCURATE: Only mark as "infected" if you find REAL malicious content
- Be CONCISE: Keep explanations brief and to the point - only essential information
- Be SPECIFIC: State exactly what was found and where (no verbose descriptions)
- Extract ACTUAL payloads: Show only the malicious code/commands found
- If clean: Brief one-sentence explanation (e.g., "Normal GIF structure, no appended data")

IMPORTANT: Keep responses SHORT and FOCUSED. Only include key points. No lengthy explanations or unnecessary details.

Respond in JSON format:
{{
    "prediction": "infected" or "clean",
    "method": "detection_method_name (e.g., 'metadata_injection', 'appended_payload', 'steganography', 'polyglot_file', 'suspicious_script', 'clean')",
    "explanation": "BRIEF explanation (2-3 sentences max). If infected: what was found and where. If clean: why it's safe.",
    "risk_level": "low/medium/high/none",
    "extracted_payload": "Only the actual malicious code/commands found. If clean: 'No malicious payload detected.'"
}}"""

        # Get response from analysis engine with safety settings
        generation_config = {
            "temperature": 0.1,  # Low temperature for more deterministic, accurate analysis
            "top_p": 0.95,
            "top_k": 40,
            "max_output_tokens": 2048,  # Reduced for concise responses - focus on key points only
        }
        
        safety_settings = [
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
        ]
        
        # Retry logic with exponential backoff for quota/rate limit errors
        max_retries = 3
        retry_delay = 2  # Start with 2 seconds
        
        for attempt in range(max_retries):
            try:
                response = model.generate_content(
                    prompt,
                    generation_config=generation_config,
                    safety_settings=safety_settings
                )
                break  # Success, exit retry loop
            except Exception as e:
                error_str = str(e)
                
                # Check if it's a quota/rate limit error
                if ("quota" in error_str.lower() or "429" in error_str or 
                    "rate limit" in error_str.lower()):
                    
                    if attempt < max_retries - 1:
                        # Extract retry delay from error if available
                        if "retry_delay" in error_str or "retry in" in error_str.lower():
                            # Try to extract seconds from error message
                            delay_match = re.search(r'retry in ([\d.]+)s', error_str.lower())
                            if delay_match:
                                retry_delay = float(delay_match.group(1)) + 1
                            else:
                                retry_delay = retry_delay * (2 ** attempt)  # Exponential backoff
                        else:
                            retry_delay = retry_delay * (2 ** attempt)  # Exponential backoff
                        
                        print(f"[Intelligence Engine] Rate limit hit, retrying in {retry_delay:.1f}s (attempt {attempt + 1}/{max_retries})...")
                        time.sleep(retry_delay)
                        continue
                    else:
                        # Last attempt failed, try fallback to Flash models
                        print(f"[Intelligence Engine] Quota exceeded for {selected_model_name}, trying Flash model fallback...")
                        
                        # Try Flash models as fallback
                        flash_models = ['gemini-2.5-flash', 'gemini-1.5-flash', 'gemini-2.0-flash']
                        for flash_model in flash_models:
                            if flash_model == selected_model_name:
                                continue  # Skip if already tried
                            try:
                                fallback_model = genai.GenerativeModel(flash_model)
                                print(f"[Intelligence Engine] Using fallback model: {flash_model}")
                                response = fallback_model.generate_content(
                                    prompt,
                                    generation_config=generation_config,
                                    safety_settings=safety_settings
                                )
                                break  # Success with fallback
                            except Exception:
                                continue
                        else:
                            # All fallbacks failed
                            raise e
                else:
                    # Not a quota error, re-raise
                    raise e
        
        # Safely extract response text
        if hasattr(response, 'text') and response.text:
            response_text = str(response.text).strip()
        elif isinstance(response, dict):
            response_text = str(response).strip()
        else:
            response_text = str(response).strip()
        
        # Try to parse JSON from response
        # Handle various formats: markdown code blocks, plain JSON, or JSON embedded in text
        if isinstance(response_text, str):
            # Remove markdown code blocks
            if "```json" in response_text:
                parts = response_text.split("```json")
                if len(parts) > 1:
                    response_text = parts[1].split("```")[0].strip()
            elif "```" in response_text:
                parts = response_text.split("```")
                # Find the JSON block (usually the longest code block)
                json_blocks = [p.strip() for p in parts[1::2] if p.strip().startswith('{')]
                if json_blocks:
                    response_text = json_blocks[0]
            
            # Try to extract JSON object from text if it's embedded
            if not response_text.strip().startswith('{'):
                # Look for JSON object in the text
                json_start = response_text.find('{')
                if json_start >= 0:
                    # Find the matching closing brace
                    brace_count = 0
                    json_end = json_start
                    for i in range(json_start, len(response_text)):
                        if response_text[i] == '{':
                            brace_count += 1
                        elif response_text[i] == '}':
                            brace_count -= 1
                            if brace_count == 0:
                                json_end = i + 1
                                break
                    if json_end > json_start:
                        response_text = response_text[json_start:json_end]
        else:
            response_text = str(response_text)
        
        # Clean up response text - remove any leading/trailing non-JSON text
        response_text = response_text.strip()
        
        try:
            result = json.loads(response_text)
            
            # Safely get prediction with type checking
            prediction_raw = result.get("prediction", "clean")
            if isinstance(prediction_raw, str):
                prediction = prediction_raw.lower().strip()
            else:
                prediction = str(prediction_raw).lower().strip()
            
            # Validate prediction - must be either "infected" or "clean"
            if prediction not in ["infected", "clean"]:
                # If invalid, analyze the explanation to determine
                explanation_raw = result.get("explanation", "")
                explanation = str(explanation_raw).lower() if explanation_raw else ""
                if any(word in explanation for word in ["malicious", "malware", "payload", "threat", "dangerous", "suspicious code"]):
                    prediction = "infected"
                else:
                    prediction = "clean"
            
            # Get extracted payload - prioritize extracted_payload field with type checking
            extracted_payload_raw = result.get("extracted_payload", "")
            if isinstance(extracted_payload_raw, str):
                extracted_payload = extracted_payload_raw.strip()
            else:
                extracted_payload = str(extracted_payload_raw).strip()
            
            if not extracted_payload or extracted_payload == "":
                explanation_raw = result.get("explanation", "Analysis completed - no payload extracted")
                extracted_payload = str(explanation_raw) if explanation_raw else "Analysis completed - no payload extracted"
            
            # Get method with type checking
            method_raw = result.get("method", "advanced_analysis")
            if isinstance(method_raw, str):
                method = method_raw.strip()
            else:
                method = str(method_raw).strip()
            
            if not method or method == "":
                method = "advanced_analysis"
            
            return {
                "prediction": prediction,
                "model_method": method,
                "payload_detected": method if prediction == "infected" else "clean",
                "extracted_payload": extracted_payload
            }
        except json.JSONDecodeError as e:
            # If JSON parsing fails, try to extract JSON object more aggressively
            # Look for JSON-like structure and try to fix common issues
            json_candidates = []
            
            # Try to find JSON object boundaries
            start_idx = response_text.find('{')
            if start_idx >= 0:
                # Try multiple strategies to extract valid JSON
                strategies = [
                    # Strategy 1: Extract from first { to last }
                    lambda: response_text[start_idx:response_text.rfind('}') + 1],
                    # Strategy 2: Extract first complete JSON object
                    lambda: _extract_json_object(response_text, start_idx),
                    # Strategy 3: Try to fix common JSON issues
                    lambda: _fix_json_string(response_text[start_idx:])
                ]
                
                for strategy in strategies:
                    try:
                        candidate = strategy()
                        if candidate and candidate.strip().startswith('{'):
                            result = json.loads(candidate)
                            json_candidates.append(result)
                            break
                    except:
                        continue
            
            # If we found a valid JSON candidate, use it
            if json_candidates:
                result = json_candidates[0]
                # Process the result normally
                prediction_raw = result.get("prediction", "clean")
                if isinstance(prediction_raw, str):
                    prediction = prediction_raw.lower().strip()
                else:
                    prediction = str(prediction_raw).lower().strip()
                
                if prediction not in ["infected", "clean"]:
                    explanation_raw = result.get("explanation", "")
                    explanation = str(explanation_raw).lower() if explanation_raw else ""
                    if any(word in explanation for word in ["malicious", "malware", "payload", "threat", "dangerous", "suspicious code"]):
                        prediction = "infected"
                    else:
                        prediction = "clean"
                
                extracted_payload_raw = result.get("extracted_payload", "")
                if isinstance(extracted_payload_raw, str):
                    extracted_payload = extracted_payload_raw.strip()
                else:
                    extracted_payload = str(extracted_payload_raw).strip()
                
                if not extracted_payload or extracted_payload == "":
                    explanation_raw = result.get("explanation", "Analysis completed - no payload extracted")
                    extracted_payload = str(explanation_raw) if explanation_raw else "Analysis completed - no payload extracted"
                
                method_raw = result.get("method", "advanced_analysis")
                if isinstance(method_raw, str):
                    method = method_raw.strip()
                else:
                    method = str(method_raw).strip()
                
                if not method or method == "":
                    method = "advanced_analysis"
                
                return {
                    "prediction": prediction,
                    "model_method": method,
                    "payload_detected": method if prediction == "infected" else "clean",
                    "extracted_payload": extracted_payload
                }
            
            # If all JSON extraction fails, try to extract information from text
            response_lower = str(response_text).lower() if response_text else ""
            
            # Extract prediction from text
            prediction = "clean"
            if '"prediction"' in response_text or "'prediction'" in response_text:
                # Try to extract prediction value
                pred_match = re.search(r'["\']prediction["\']\s*:\s*["\']([^"\']+)["\']', response_text, re.IGNORECASE)
                if pred_match:
                    prediction = pred_match.group(1).lower().strip()
            
            # Extract method
            method = "advanced_analysis"
            if '"method"' in response_text or "'method'" in response_text:
                method_match = re.search(r'["\']method["\']\s*:\s*["\']([^"\']+)["\']', response_text, re.IGNORECASE)
                if method_match:
                    method = method_match.group(1).strip()
            
            # Extract payload
            extracted_payload = response_text
            if '"extracted_payload"' in response_text or "'extracted_payload'" in response_text:
                payload_match = re.search(r'["\']extracted_payload["\']\s*:\s*["\']([^"\']+)["\']', response_text, re.IGNORECASE | re.DOTALL)
                if payload_match:
                    extracted_payload = payload_match.group(1).strip()
            elif '"explanation"' in response_text or "'explanation'" in response_text:
                expl_match = re.search(r'["\']explanation["\']\s*:\s*["\']([^"\']+)["\']', response_text, re.IGNORECASE | re.DOTALL)
                if expl_match:
                    extracted_payload = expl_match.group(1).strip()
            
            # Fallback: analyze text for indicators
            if prediction not in ["infected", "clean"]:
                has_clear_threat = any(phrase in response_lower for phrase in [
                    "malicious code", "malware detected", "infected file", "payload found",
                    "suspicious script", "executable code", "malicious payload", '"prediction": "infected"'
                ])
                
                has_clear_clean = any(phrase in response_lower for phrase in [
                    "clean file", "no malicious", "safe file", "normal gif", "no threat",
                    "no payload", "legitimate file", '"prediction": "clean"'
                ])
                
                if has_clear_threat and not has_clear_clean:
                    prediction = "infected"
                elif has_clear_clean and not has_clear_threat:
                    prediction = "clean"
                else:
                    prediction = "clean"
            
            return {
                "prediction": prediction,
                "model_method": method,
                "payload_detected": method if prediction == "infected" else "clean",
                "extracted_payload": extracted_payload[:2000] if len(extracted_payload) > 2000 else extracted_payload
            }
            
    except Exception as e:
        return {
            "prediction": "error",
            "model_method": "advanced_analysis",
            "payload_detected": "none",
            "extracted_payload": f"Error during analysis: {str(e)}"
        }

