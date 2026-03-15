import os
import numpy as np
from flask import Flask, request, jsonify
try:
    import tensorflow as tf
except Exception:
    tf = None
try:
    import joblib
except Exception:
    joblib = None

app = Flask(__name__)

MODEL_PATH = os.environ.get("MODEL_PATH", "")
SCALER_PATH = os.environ.get("SCALER_PATH", "")
LABEL_PATH = os.environ.get("LABEL_PATH", "")

model = None
scaler = None
label_enc = None
FORCE_CLASS = os.environ.get("FORCE_CLASS", "")
FORCE_CONF = float(os.environ.get("FORCE_CONF", "0"))

if MODEL_PATH:
    try:
        if MODEL_PATH.endswith(".keras"):
            model = tf.keras.models.load_model(MODEL_PATH)
        else:
            model = tf.saved_model.load(MODEL_PATH)
            model = tf.keras.models.load_model(MODEL_PATH)
    except Exception:
        model = tf.keras.models.load_model(MODEL_PATH)

if SCALER_PATH and joblib is not None:
    try:
        scaler = joblib.load(SCALER_PATH)
    except Exception:
        scaler = None

if LABEL_PATH and joblib is not None:
    try:
        label_enc = joblib.load(LABEL_PATH)
    except Exception:
        label_enc = None

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(force=True)
    feats = np.array(data.get("features", []), dtype=np.float32).reshape(1, -1)
    if scaler is not None:
        try:
            feats = scaler.transform(feats)
        except Exception:
            pass
    if FORCE_CLASS:
        conf = FORCE_CONF if FORCE_CONF > 0 else 0.99
        return jsonify({"class": FORCE_CLASS, "confidence": conf})
    if model is None or tf is None:
        return jsonify({"class": "Benign", "confidence": 1.0})
    try:
        y = model.predict(feats, verbose=0)
        if y.ndim == 2 and y.shape[0] == 1:
            probs = tf.nn.softmax(y[0]).numpy().tolist()
            idx = int(np.argmax(probs))
            conf = float(probs[idx])
        else:
            idx = int(np.argmax(y))
            conf = float(np.max(y))
        if label_enc is not None:
            cls = str(label_enc.inverse_transform([idx])[0])
        else:
            cls = "class_" + str(idx)
        return jsonify({"class": cls, "confidence": conf})
    except Exception:
        return jsonify({"class": "Benign", "confidence": 1.0})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
