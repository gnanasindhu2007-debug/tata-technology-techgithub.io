import hashlib
from pathlib import Path

import numpy as np


class DeepShieldModel:
    """Demo edge-AI classifier with optional TensorFlow model loading.

    If a trained Keras model is available at models/deepshield_model.h5, the
    class can be extended to use it. The fallback keeps the project runnable
    for presentations without external model files.
    """

    def __init__(self):
        self.labels = ["Safe", "Suspicious", "Malware"]
        self.keras_model = None
        model_path = Path(__file__).resolve().parent / "models" / "deepshield_model.h5"
        if model_path.exists():
            try:
                from tensorflow.keras.models import load_model

                self.keras_model = load_model(model_path)
            except Exception:
                self.keras_model = None

    def predict(self, file_path, features):
        vector = self._feature_vector(file_path, features)
        if self.keras_model is not None:
            prediction = self.keras_model.predict(np.array([vector]), verbose=0)[0]
            index = int(np.argmax(prediction))
            confidence = float(prediction[index] * 100)
            classification = self.labels[index]
        else:
            score = self._risk_score(features)
            if score >= 70:
                classification = "Malware"
            elif score >= 38:
                classification = "Suspicious"
            else:
                classification = "Safe"
            confidence = min(98.0, max(55.0, 52.0 + score * 0.6))

        severity = {
            "Safe": "Low",
            "Suspicious": "Medium",
            "Malware": "High",
        }[classification]
        insights = self._insights(classification, features)
        return {
            "classification": classification,
            "confidence": round(confidence, 2),
            "severity": severity,
            "insights": insights,
        }

    def _feature_vector(self, file_path, features):
        suffix_score = sum(ord(ch) for ch in features["extension"]) % 100
        return np.array(
            [
                min(features["size"] / 10_000_000, 1.0),
                features["entropy"] / 8.0,
                suffix_score / 100,
                int(hashlib.sha256(Path(file_path).read_bytes()).hexdigest()[:2], 16) / 255,
            ],
            dtype=np.float32,
        )

    def _risk_score(self, features):
        risky_extensions = {".exe", ".dll", ".bin", ".img", ".hex", ".elf", ".apk", ".jar"}
        score = 10
        if features["extension"] in risky_extensions:
            score += 28
        if features["entropy"] > 7.1:
            score += 32
        elif features["entropy"] > 6.2:
            score += 18
        if features["size"] > 8_000_000:
            score += 12
        if features["sha256"].startswith(("00", "ff", "a5", "5a")):
            score += 14
        return min(score, 100)

    def _insights(self, classification, features):
        notes = []
        if features["extension"] in {".bin", ".img", ".hex", ".elf"}:
            notes.append("Automotive firmware-style file detected.")
        if features["entropy"] > 7.1:
            notes.append("High entropy suggests packing, encryption, or obfuscation.")
        elif features["entropy"] > 6.2:
            notes.append("Moderate entropy requires ECU security review.")
        else:
            notes.append("Entropy profile appears normal for this demo scan.")
        if classification == "Malware":
            notes.append("Block deployment and perform reverse engineering before OTA release.")
        elif classification == "Suspicious":
            notes.append("Send to an automotive security engineer for manual validation.")
        else:
            notes.append("No major malware pattern was detected by the edge model.")
        return " ".join(notes)
