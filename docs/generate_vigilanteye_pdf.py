"""
Generate a PDF document explaining:
1) CNN model architecture + how it detects GIF malware/stego patterns
2) Embedding methods implemented in embedding_engine.py

Output:
  docs/VigilantEye_Documentation.pdf

Usage:
  pip install fpdf2
  python docs/generate_vigilanteye_pdf.py
"""

from __future__ import annotations

from datetime import date
from pathlib import Path


def _require_fpdf():
    try:
        # fpdf2
        from fpdf import FPDF  # type: ignore

        return FPDF
    except Exception as e:  # pragma: no cover
        raise SystemExit(
            "Missing dependency: fpdf2\n"
            "Install with: pip install fpdf2\n"
            f"Original error: {e}"
        )


def build_pdf(output_path: Path) -> None:
    FPDF = _require_fpdf()

    pdf = FPDF(format="A4", unit="mm")
    pdf.set_auto_page_break(auto=True, margin=14)
    pdf.add_page()

    def safe(text: str) -> str:
        """
        fpdf core fonts are latin-1; sanitize common unicode chars to ASCII.
        """
        replacements = {
            "\u2014": "-",  # em dash
            "\u2013": "-",  # en dash
            "\u2019": "'",  # right single quote
            "\u2018": "'",  # left single quote
            "\u201c": "\"",  # left double quote
            "\u201d": "\"",  # right double quote
            "\u2022": "-",  # bullet
            "\u00a0": " ",  # non-breaking space
        }
        for k, v in replacements.items():
            text = text.replace(k, v)
        # Last-resort: replace anything not representable in latin-1.
        return text.encode("latin-1", "replace").decode("latin-1")

    # ---- helpers
    def h1(text: str) -> None:
        pdf.set_font("Helvetica", "B", 18)
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, 9, safe(text))
        pdf.ln(2)

    def h2(text: str) -> None:
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, 7, safe(text))
        pdf.ln(1)

    def p(text: str) -> None:
        pdf.set_font("Helvetica", "", 11)
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, 5.5, safe(text))
        pdf.ln(1.5)

    def mono_block(text: str) -> None:
        pdf.set_font("Courier", "", 9.5)
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, 4.6, safe(text))
        pdf.ln(1.5)

    def bullets(items: list[str]) -> None:
        pdf.set_font("Helvetica", "", 11)
        for it in items:
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(0, 5.5, safe(f"- {it}"))
        pdf.ln(1.5)

    # ---- Title
    h1("VigilantEye - CNN Model & GIF Embedding Documentation")
    p(f"Generated: {date.today().isoformat()}")

    # ---- Section: Executive summary
    h2("1) Executive Summary")
    p(
        "VigilantEye analyzes GIF files using a hybrid approach:\n"
        "1) A lightweight 3D-CNN that looks for learned visual/temporal artifacts across frames.\n"
        "2) A rules/signature extractor that looks for suspicious embedded payload patterns.\n"
        "3) (Optional) LLM-based analysis for higher-level reasoning and reporting.\n"
        "This document explains how the CNN is structured and how the embedding demo hides payload data inside GIFs."
    )

    # ---- Section: CNN architecture (based on test_model.py)
    h2("2) CNN Model Architecture (MultiHeadCNN)")
    p(
        "Source of truth: test_model.py\n\n"
        "The model is a 3D-CNN (Conv3d) over a fixed-length clip of GIF frames. "
        "It uses one shared convolutional backbone and two output heads:\n"
        "• Head A: binary classification (clean vs infected)\n"
        "• Head B: embedding method classification (which embedding technique is most likely present)"
    )

    h2("2.1 Input Preprocessing")
    bullets(
        [
            "GIF is decoded into frames; up to FRAMES=25 frames are used.",
            "Each frame is converted to RGB, resized to IMAGE_SIZE=(100, 100), and converted to a tensor.",
            "If the GIF has fewer than 25 frames, the last frame is repeated to reach 25.",
            "Final tensor shape (per sample): [C=3, T=25, H=100, W=100].",
            "Device: CUDA if available, otherwise CPU.",
        ]
    )

    h2("2.2 Layer-by-Layer Structure (as implemented)")
    p("The backbone is:")
    mono_block(
        "Conv3d(3 -> 32, kernel=3, padding=1)\n"
        "BatchNorm3d(32)\n"
        "ReLU\n"
        "MaxPool3d(kernel=(1,2,2))\n"
        "Conv3d(32 -> 64, kernel=3, padding=1)\n"
        "BatchNorm3d(64)\n"
        "ReLU\n"
        "MaxPool3d(kernel=(1,2,2))\n"
        "Flatten\n"
        "Linear(64 * 25 * 25 * 25 -> 256)\n"
        "Head(class): Linear(256 -> 2)\n"
        "Head(method): Linear(256 -> N_methods)"
    )

    h2("2.3 Tensor Shapes (conceptual)")
    mono_block(
        "Input:        [B,  3, 25, 100, 100]\n"
        "Conv3d:       [B, 32, 25, 100, 100]\n"
        "Pool (1,2,2): [B, 32, 25,  50,  50]\n"
        "Conv3d:       [B, 64, 25,  50,  50]\n"
        "Pool (1,2,2): [B, 64, 25,  25,  25]\n"
        "Flatten:      [B, 1,000,000]\n"
        "Shared FC:    [B, 256]\n"
        "Class head:   [B, 2]\n"
        "Method head:  [B, N_methods]"
    )

    h2("2.4 How the CNN Detects Malware (high-level)")
    p(
        "The CNN does not execute the GIF and does not run any embedded code. "
        "Instead, it learns statistical/visual/temporal cues from training data.\n\n"
        "Examples of cues the model may learn (depending on the dataset):"
    )
    bullets(
        [
            "Unnatural pixel-level noise patterns (common in steganography/LSB-style embeddings).",
            "Frame-to-frame inconsistencies in animated GIFs.",
            "Artifacts introduced by re-encoding/optimization after tampering.",
            "Distribution shifts correlated with specific embedding techniques.",
        ]
    )
    p(
        "Inference logic (simplified):\n"
        "• infected/clean = argmax(class_head)\n"
        "• method = argmax(method_head)\n\n"
        "Note: The model output is a prediction, not proof. Pair it with signature/rule checks and safe file handling."
    )

    # ---- Section: Embedding methods
    h2("3) Embedding Methods (Demo) — What We Embed and Where It Lives")
    p(
        "Source of truth: embedding_engine.py\n\n"
        "The embedding demo shows how payload data can be hidden inside a GIF. "
        "Important security note: a GIF is an image format and is not an executable program. "
        "Embedded payload data remains dormant unless an external trigger extracts and executes it."
    )

    h2("3.1 Method 1 — Append After Terminator")
    bullets(
        [
            "What it does: writes extra bytes after the GIF terminator.",
            "Where it lives: after the end-of-file marker (the viewer typically ignores it).",
            "Why it can work: many decoders stop parsing at the terminator and ignore trailing bytes.",
            "Detection: check for data after terminator / abnormal size / trailing readable strings.",
        ]
    )

    h2("3.2 Method 2 — GIF Comment Extension")
    bullets(
        [
            "What it does: inserts a Comment Extension block into the GIF structure.",
            "Where it lives: a standard extension area intended for comments/metadata.",
            "Why it can work: comments are valid per spec and usually not displayed.",
            "Detection: parse extension blocks and inspect comment contents for suspicious patterns.",
        ]
    )

    h2("3.3 Method 3 — Base64 Encoded Append")
    bullets(
        [
            "What it does: Base64-encodes the payload text and appends it after the GIF terminator with a marker.",
            "Where it lives: trailing bytes, but text looks less obvious due to Base64 encoding.",
            "Detection: search for markers (e.g., base64:) and attempt safe decode + inspection.",
        ]
    )

    h2("3.4 Method 4 — LSB Steganography")
    bullets(
        [
            "What it does: hides payload bits in the least-significant bits of pixel channels across frames.",
            "Where it lives: distributed throughout pixel data (harder to spot by casual inspection).",
            "Trade-offs: stealthy but limited by image capacity and requires careful extraction logic.",
            "Detection: statistical steganalysis, LSB plane analysis, anomaly tests (e.g., chi-square).",
        ]
    )

    # ---- Section: How we explain embedding in the UI (LLM)
    h2("4) How the App Explains Embedding (Token-Efficient)")
    p(
        "To avoid wasting tokens, the app generates a short, structured explanation with exactly 4 lines:\n"
        "Embedding / Placement / Detection / Risk.\n\n"
        "This keeps outputs consistent, professional, and small while still being useful."
    )

    # ---- Section: Operational notes
    h2("5) Operational Notes / Safety")
    bullets(
        [
            "Do not execute any extracted payload. Treat it as untrusted data.",
            "Use least privilege for file processing services and isolate uploads.",
            "The demo is educational; in production, implement stricter validation and sandboxing.",
        ]
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(output_path))


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    out = repo_root / "docs" / "VigilantEye_Documentation.pdf"
    build_pdf(out)
    print(f"PDF generated: {out}")


if __name__ == "__main__":
    main()


