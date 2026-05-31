# Flow 02 - ML Training and Inference

## Objective
Train and run anomaly model on network features.

## Primary Files
- `Backend/ML/mode-train.ipynb`
- `Backend/ML/feature_aggregator.py`
- `Backend/ML/validation_layer.py`
- `Backend/ML/live_track_FIXED.ipynb`
- `Backend/ML/models/*`

## What It Does
- Trains model and saves artifacts:
  - `model.pkl`
  - `scaler.pkl`
  - `encoders.pkl`
  - `features.pkl`
  - `target_encoder.pkl`
- Extracts KDD-style features from packets.
- Validates and post-processes predictions.

## Current Role In Final Architecture
- This is the ML core used by the API service (`TrafficAnalyzer`).
- Real-time predictions are generated from live packets.
