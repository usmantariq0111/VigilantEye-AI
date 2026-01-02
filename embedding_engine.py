"""
GIF Embedding and Steganography Engine
Demonstrates various techniques for embedding malware/payloads into GIF files.
"""
import os
import base64
import time
import re
from PIL import Image, ImageSequence
import io

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    import google.generativeai as genai
    from google.api_core import exceptions as google_exceptions
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False
    google_exceptions = None


def embed_payload_append(gif_path, payload_text, output_path):
    """
    Method 1: Append payload after GIF terminator (0x00 0x3B)
    This is the simplest method - just append data after the GIF ends.
    """
    with open(gif_path, 'rb') as f:
        gif_data = f.read()
    
    # Find GIF terminator
    terminator = b'\x00\x3B'
    terminator_pos = gif_data.rfind(terminator)
    
    if terminator_pos == -1:
        # If no terminator found, append at the end
        terminator_pos = len(gif_data) - 2
    
    # Split GIF and append payload
    gif_part = gif_data[:terminator_pos + 2]
    payload_bytes = payload_text.encode('utf-8')
    
    # Create embedded GIF
    embedded = gif_part + b'\n<!--' + payload_bytes + b'-->\n'
    
    with open(output_path, 'wb') as f:
        f.write(embedded)
    
    return {
        'method': 'append_after_terminator',
        'description': 'Payload appended after GIF terminator (0x00 0x3B)',
        'offset': terminator_pos + 2,
        'payload_size': len(payload_bytes)
    }


def embed_payload_comment(gif_path, payload_text, output_path):
    """
    Method 2: Embed payload in GIF comment extension
    GIF supports comment extensions (0x21 0xFE) that can contain text.
    """
    with open(gif_path, 'rb') as f:
        gif_data = bytearray(f.read())
    
    # Find a good insertion point (after header, before image data)
    # Look for Image Separator (0x2C) or use position after Logical Screen Descriptor
    insert_pos = 13  # After GIF header (6 bytes) + Logical Screen Descriptor (7 bytes)
    
    # Create comment extension block
    # Structure: 0x21 (Extension Introducer) + 0xFE (Comment Label) + [data blocks]
    payload_bytes = payload_text.encode('utf-8')
    
    # Split payload into 255-byte chunks (GIF comment limit per block)
    chunks = [payload_bytes[i:i+255] for i in range(0, len(payload_bytes), 255)]
    
    comment_blocks = bytearray()
    for chunk in chunks:
        comment_blocks.append(0x21)  # Extension Introducer
        comment_blocks.append(0xFE)  # Comment Label
        comment_blocks.append(len(chunk))  # Block size
        comment_blocks.extend(chunk)
    comment_blocks.append(0x00)  # Terminator
    
    # Insert comment extension
    embedded = gif_data[:insert_pos] + bytes(comment_blocks) + gif_data[insert_pos:]
    
    with open(output_path, 'wb') as f:
        f.write(embedded)
    
    return {
        'method': 'comment_extension',
        'description': 'Payload embedded in GIF comment extension (0x21 0xFE)',
        'offset': insert_pos,
        'payload_size': len(payload_bytes)
    }


def embed_payload_base64_append(gif_path, payload_text, output_path):
    """
    Method 3: Base64 encode payload and append
    Encodes the payload in base64 before appending for obfuscation.
    """
    with open(gif_path, 'rb') as f:
        gif_data = f.read()
    
    # Base64 encode payload
    payload_b64 = base64.b64encode(payload_text.encode('utf-8')).decode('utf-8')
    
    # Find terminator
    terminator = b'\x00\x3B'
    terminator_pos = gif_data.rfind(terminator)
    if terminator_pos == -1:
        terminator_pos = len(gif_data) - 2
    
    # Append base64 encoded payload
    gif_part = gif_data[:terminator_pos + 2]
    embedded = gif_part + b'\nbase64:' + payload_b64.encode('utf-8') + b'\n'
    
    with open(output_path, 'wb') as f:
        f.write(embedded)
    
    return {
        'method': 'base64_append',
        'description': 'Base64-encoded payload appended after GIF terminator',
        'offset': terminator_pos + 2,
        'payload_size': len(payload_text.encode('utf-8')),
        'encoded_size': len(payload_b64)
    }


def embed_payload_lsb(gif_path, payload_text, output_path):
    """
    Method 4: LSB (Least Significant Bit) Steganography
    Hides payload in the least significant bits of pixel data.
    Note: This is a simplified version for demonstration.
    Optimized for memory efficiency.
    """
    try:
        # Limit payload size to prevent memory issues
        MAX_PAYLOAD_SIZE = 10000  # 10KB max for LSB
        if len(payload_text) > MAX_PAYLOAD_SIZE:
            payload_text = payload_text[:MAX_PAYLOAD_SIZE]
        
        img = Image.open(gif_path)
        frames = []
        payload_bits = ''.join(format(ord(c), '08b') for c in payload_text)
        payload_bits += '1111111111111110'  # End marker
        
        bit_index = 0
        frame_count = 0
        MAX_FRAMES = 50  # Limit frames to prevent memory issues
        
        for frame in ImageSequence.Iterator(img):
            if frame_count >= MAX_FRAMES:
                break  # Limit processing to prevent memory issues
                
            frame = frame.convert('RGB')
            pixels = list(frame.getdata())
            
            if bit_index < len(payload_bits):
                new_pixels = []
                pixel_count = 0
                MAX_PIXELS_PER_FRAME = 100000  # Limit pixels per frame
                
                for pixel in pixels:
                    if pixel_count >= MAX_PIXELS_PER_FRAME:
                        new_pixels.append(pixel)
                        continue
                        
                    if bit_index < len(payload_bits):
                        r, g, b = pixel
                        # Modify LSB of red channel
                        r = (r & 0xFE) | int(payload_bits[bit_index])
                        bit_index += 1
                        if bit_index < len(payload_bits):
                            g = (g & 0xFE) | int(payload_bits[bit_index])
                            bit_index += 1
                        new_pixels.append((r, g, b))
                        pixel_count += 1
                    else:
                        new_pixels.append(pixel)
                frame.putdata(new_pixels)
            
            frames.append(frame)
            frame_count += 1
        
        # Save as GIF with optimization
        if frames:
            frames[0].save(
                output_path,
                save_all=True,
                append_images=frames[1:],
                duration=img.info.get('duration', 100),
                loop=img.info.get('loop', 0),
                optimize=True  # Optimize GIF size
            )
        
        # Clean up
        img.close()
        del frames
        
        return {
            'method': 'lsb_steganography',
            'description': 'Payload hidden using LSB (Least Significant Bit) steganography in pixel data',
            'offset': 'distributed across pixels',
            'payload_size': len(payload_text.encode('utf-8')),
            'bits_used': min(bit_index, len(payload_bits))
        }
    except Exception as e:
        return {
            'method': 'lsb_steganography',
            'description': f'LSB embedding failed: {str(e)}',
            'error': str(e)
        }


def get_llm_explanation(embedding_method, payload_text, embedding_details):
    """
    Use LLM to generate explanation of the embedding technique and steganography.
    """
    if not LLM_AVAILABLE:
        return "LLM not available. Please install google-generativeai package."
    
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return "GEMINI_API_KEY not set. Please configure your API key in .env file."
    
    try:
        genai.configure(api_key=api_key)
        
        # Use best PRO models for detailed explanations - optimized for PRO accounts
        # Priority for PRO accounts:
        #   1) Gemini 2.5 Pro (latest stable PRO - best reasoning and explanations)
        #   2) Gemini 3 Pro Preview (latest preview PRO - cutting-edge capabilities)
        #   3) Gemini 1.5 Pro (stable PRO - excellent for detailed technical explanations)
        #   4) Gemini 2.5 Flash (fast PRO alternative)
        #   5) Gemini 3 Flash Preview (fast preview alternative)
        #   6) Flash models as fallbacks
        model_names = [
            'gemini-2.5-pro',             # Latest stable PRO - best for detailed explanations
            'gemini-3-pro-preview',        # Latest preview PRO - cutting-edge capabilities
            'gemini-1.5-pro',              # Stable PRO - excellent for technical content
            'gemini-2.5-flash',            # Fast PRO alternative
            'gemini-3-flash-preview',       # Fast preview alternative
            'gemini-2.0-flash',            # Stable Flash fallback
            'gemini-1.5-flash'             # Widely available Flash fallback
        ]
        
        model = None
        selected_model_name = None
        last_error = None
        
        for model_name in model_names:
            try:
                model = genai.GenerativeModel(model_name)
                selected_model_name = model_name
                break
            except Exception as e:
                last_error = str(e)
                # If it's a quota error, try next model (especially Flash models)
                if "quota" in str(e).lower() or "429" in str(e):
                    print(f"[Embedding Engine] Quota exceeded for {model_name}, trying next model...")
                    continue
                continue
        
        if model is None:
            error_msg = "No compatible LLM model available."
            if last_error and "quota" in last_error.lower():
                error_msg += "\n\n⚠️ Quota Error: Your API key has hit rate limits. "
                error_msg += "This usually means:\n"
                error_msg += "1. You're on the free tier (PRO models require paid plan)\n"
                error_msg += "2. You've exceeded your daily/minute rate limits\n"
                error_msg += "3. Billing is not enabled for your Google Cloud project\n\n"
                error_msg += "Solutions:\n"
                error_msg += "- Enable billing in Google Cloud Console\n"
                error_msg += "- Upgrade to a paid plan for PRO model access\n"
                error_msg += "- Wait for rate limit reset (check: https://ai.dev/usage)\n"
                error_msg += "- The app will automatically try Flash models which have higher free tier limits"
            return error_msg
        
        # Log which model is being used (for debugging)
        if selected_model_name:
            print(f"[Embedding Engine] Using model: {selected_model_name}")
        
        # Keep the output small + structured to avoid wasting tokens/quota.
        # We intentionally do NOT ask for long explanations or extra sections.
        prompt = f"""You are a cybersecurity analyst. Return ONLY the following 4 sections, each 1 sentence, with no extra text.

Embedding method: {embedding_method}
Method description: {embedding_details.get('description', 'N/A')}
Payload size: {embedding_details.get('payload_size', 'N/A')} bytes
Offset: {embedding_details.get('offset', 'N/A')}

Format EXACTLY like this:
Embedding: <one sentence>
Placement: <one sentence>
Detection: <one sentence>
Risk: <one sentence>

Rules:
- No preface, no conclusion, no bullet points, no markdown
- Keep it practical and specific to GIF structure
- Max ~60 words total"""

        generation_config = {
            "temperature": 0.3,  # Lower temperature for consistent structured output
            "top_p": 0.9,
            "top_k": 40,
            # Hard cap to prevent long responses and reduce token usage/cost.
            "max_output_tokens": 220,
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
                        
                        print(f"[Embedding Engine] Rate limit hit, retrying in {retry_delay:.1f}s (attempt {attempt + 1}/{max_retries})...")
                        time.sleep(retry_delay)
                        continue
                    else:
                        # Last attempt failed, try fallback to Flash models
                        print(f"[Embedding Engine] Quota exceeded for {selected_model_name}, trying Flash model fallback...")
                        
                        # Try Flash models as fallback
                        flash_models = ['gemini-2.5-flash', 'gemini-1.5-flash', 'gemini-2.0-flash']
                        for flash_model in flash_models:
                            if flash_model == selected_model_name:
                                continue  # Skip if already tried
                            try:
                                fallback_model = genai.GenerativeModel(flash_model)
                                print(f"[Embedding Engine] Using fallback model: {flash_model}")
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
        
        if hasattr(response, 'text') and response.text:
            return response.text.strip()
        else:
            return str(response).strip()
            
    except Exception as e:
        return f"Error generating LLM explanation: {str(e)}"


def embed_payload(gif_path, payload_text, method='append', output_path=None):
    """
    Main function to embed payload into GIF using specified method.
    
    Methods:
    - 'append': Append after terminator
    - 'comment': Embed in comment extension
    - 'base64': Base64 encode and append
    - 'lsb': LSB steganography
    """
    if output_path is None:
        base_name = os.path.splitext(os.path.basename(gif_path))[0]
        # Use static/uploads/embedded directory to match Flask's static file serving
        upload_dir = os.path.dirname(gif_path)
        output_dir = os.path.join(upload_dir, 'embedded')
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, f"{base_name}_embedded_{method}.gif")
    
    method_map = {
        'append': embed_payload_append,
        'comment': embed_payload_comment,
        'base64': embed_payload_base64_append,
        'lsb': embed_payload_lsb
    }
    
    if method not in method_map:
        raise ValueError(f"Unknown embedding method: {method}. Choose from: {list(method_map.keys())}")
    
    embedding_func = method_map[method]
    embedding_details = embedding_func(gif_path, payload_text, output_path)
    
    return {
        'output_path': output_path,
        'method': method,
        'details': embedding_details,
        'original_size': os.path.getsize(gif_path),
        'embedded_size': os.path.getsize(output_path) if os.path.exists(output_path) else 0
    }

