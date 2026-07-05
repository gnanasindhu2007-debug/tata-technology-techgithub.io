from pathlib import Path


def create_report(row, report_dir):
    report_dir = Path(report_dir)
    report_dir.mkdir(exist_ok=True)
    path = report_dir / f"deepshield_report_{row['id']}.txt"
    content = f"""DeepShield AI Automotive Cybersecurity Report

Scan ID: {row['id']}
Engineer: {row['username']}
Filename: {row['filename']}
SHA-256: {row['file_hash']}
File Size: {row['file_size']} bytes
Classification: {row['classification']}
Confidence: {row['confidence']}%
Threat Severity: {row['severity']}
Scanned At: {row['scanned_at']}

Explainable AI Insights:
{row['insights']}

Recommendation:
Safe files may proceed to standard validation. Suspicious or Malware files
should be blocked from ECU, infotainment, diagnostic, or OTA deployment until
security review is completed.
"""
    path.write_text(content, encoding="utf-8")
    return path
