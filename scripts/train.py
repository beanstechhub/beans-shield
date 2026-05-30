"""
beans-shield ML model training script.
Generates synthetic fraud data, trains LightGBM, exports ONNX + JSON.
"""

import numpy as np
import json
import os
from pathlib import Path

import lightgbm as lgb
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.metrics import (
    roc_auc_score, precision_score, recall_score, f1_score,
    confusion_matrix, precision_recall_curve
)

np.random.seed(42)

FEATURE_NAMES = [
    "amount_normalized", "hour_sin", "hour_cos",
    "is_pix_out", "is_pix_in", "is_withdrawal", "is_swap", "is_crypto_buy",
    "velocity_count_1h", "velocity_count_24h", "velocity_amount_24h",
    "is_new_destination", "is_unusual_hour", "amount_vs_avg_24h"
]

OUTPUT_DIR = Path(__file__).parent.parent / "models"

# --- 1. Generate synthetic data ---
print("=" * 60)
print("BEANS-SHIELD MODEL TRAINING")
print("=" * 60)

N = 100_000
print(f"\n[1/6] Generating {N:,} synthetic transactions...")

amounts = np.random.lognormal(mean=9, sigma=2, size=N).clip(100, 50_000_000)
amount_normalized = amounts / 10_000_000

hours = np.random.choice(24, size=N, p=[
    0.01, 0.01, 0.01, 0.01, 0.01, 0.02, 0.04, 0.06,
    0.08, 0.08, 0.08, 0.07, 0.06, 0.06, 0.06, 0.06,
    0.05, 0.05, 0.05, 0.04, 0.03, 0.03, 0.02, 0.01
])
hour_sin = np.sin(2 * np.pi * hours / 24)
hour_cos = np.cos(2 * np.pi * hours / 24)

tx_types = np.random.choice(5, size=N, p=[0.40, 0.30, 0.15, 0.10, 0.05])
is_pix_out = (tx_types == 0).astype(float)
is_pix_in = (tx_types == 1).astype(float)
is_withdrawal = (tx_types == 2).astype(float)
is_swap = (tx_types == 3).astype(float)
is_crypto_buy = (tx_types == 4).astype(float)

velocity_count_1h = np.random.poisson(2, size=N).astype(float)
velocity_count_24h = np.random.poisson(8, size=N).astype(float)
velocity_amount_24h = np.random.lognormal(mean=10, sigma=1.5, size=N).clip(0, 50_000_000) / 10_000_000

is_new_destination = np.random.binomial(1, 0.15, size=N).astype(float)
is_unusual_hour = ((hours >= 0) & (hours < 6)).astype(float)

user_avg = np.random.lognormal(mean=9, sigma=1.5, size=N).clip(1000, 10_000_000)
amount_vs_avg_24h = amounts / user_avg

X = np.column_stack([
    amount_normalized, hour_sin, hour_cos,
    is_pix_out, is_pix_in, is_withdrawal, is_swap, is_crypto_buy,
    velocity_count_1h, velocity_count_24h, velocity_amount_24h,
    is_new_destination, is_unusual_hour, amount_vs_avg_24h
])

# --- Generate labels with realistic fraud patterns ---
y = np.zeros(N)
base_fraud_rate = 0.02
y[np.random.rand(N) < base_fraud_rate] = 1

# Pattern 1: high amount + new destination + unusual hour = 80% fraud
pattern1 = (amount_normalized > 0.5) & (is_new_destination == 1) & (is_unusual_hour == 1)
y[pattern1 & (np.random.rand(N) < 0.80)] = 1

# Pattern 2: high velocity + high amount = 70% fraud
pattern2 = (velocity_count_1h > 5) & (amount_normalized > 0.3)
y[pattern2 & (np.random.rand(N) < 0.70)] = 1

# Pattern 3: amount >> user average + new destination = 60% fraud
pattern3 = (amount_vs_avg_24h > 5) & (is_new_destination == 1)
y[pattern3 & (np.random.rand(N) < 0.60)] = 1

# Pattern 4: withdrawal + unusual hour + high velocity = 75% fraud
pattern4 = (is_withdrawal == 1) & (is_unusual_hour == 1) & (velocity_count_1h > 3)
y[pattern4 & (np.random.rand(N) < 0.75)] = 1

# Pattern 5: crypto + very high amount = 50% fraud
pattern5 = (is_crypto_buy == 1) & (amount_normalized > 0.8)
y[pattern5 & (np.random.rand(N) < 0.50)] = 1

fraud_rate = y.mean()
print(f"    Fraud rate: {fraud_rate:.2%} ({int(y.sum()):,} frauds / {N:,} total)")

# --- 2. Train/Test split ---
print("\n[2/6] Splitting train/test (80/20)...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)
print(f"    Train: {len(X_train):,} | Test: {len(X_test):,}")

# --- 3. Cross-validation ---
print("\n[3/6] Running 5-fold cross-validation...")
scale_pos_weight = (y_train == 0).sum() / max((y_train == 1).sum(), 1)

params = {
    "objective": "binary",
    "metric": "auc",
    "learning_rate": 0.05,
    "num_leaves": 63,
    "max_depth": 7,
    "min_child_samples": 50,
    "subsample": 0.8,
    "colsample_bytree": 0.8,
    "scale_pos_weight": scale_pos_weight,
    "verbose": -1,
    "n_jobs": -1,
    "random_state": 42,
}

skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_aucs = []

for fold, (train_idx, val_idx) in enumerate(skf.split(X_train, y_train)):
    X_fold_train, X_fold_val = X_train[train_idx], X_train[val_idx]
    y_fold_train, y_fold_val = y_train[train_idx], y_train[val_idx]

    ds_train = lgb.Dataset(X_fold_train, label=y_fold_train, feature_name=FEATURE_NAMES)
    ds_val = lgb.Dataset(X_fold_val, label=y_fold_val, feature_name=FEATURE_NAMES)

    model = lgb.train(
        params,
        ds_train,
        num_boost_round=500,
        valid_sets=[ds_val],
        callbacks=[lgb.early_stopping(30, verbose=False)],
    )

    preds = model.predict(X_fold_val)
    auc = roc_auc_score(y_fold_val, preds)
    cv_aucs.append(auc)
    print(f"    Fold {fold+1}: AUC = {auc:.4f}")

print(f"    Mean AUC: {np.mean(cv_aucs):.4f} (+/- {np.std(cv_aucs):.4f})")

# --- 4. Final model training ---
print("\n[4/6] Training final model on full training set...")
ds_full_train = lgb.Dataset(X_train, label=y_train, feature_name=FEATURE_NAMES)
ds_test = lgb.Dataset(X_test, label=y_test, feature_name=FEATURE_NAMES)

final_model = lgb.train(
    params,
    ds_full_train,
    num_boost_round=500,
    valid_sets=[ds_test],
    callbacks=[lgb.early_stopping(30, verbose=False)],
)

# --- 5. Evaluation ---
print("\n[5/6] Evaluating on test set...")
y_pred_proba = final_model.predict(X_test)
test_auc = roc_auc_score(y_test, y_pred_proba)

# Find optimal threshold (maximize F1)
precisions, recalls, thresholds = precision_recall_curve(y_test, y_pred_proba)
f1_scores = 2 * (precisions * recalls) / (precisions + recalls + 1e-8)
optimal_idx = np.argmax(f1_scores)
optimal_threshold = thresholds[optimal_idx] if optimal_idx < len(thresholds) else 0.5

y_pred = (y_pred_proba >= optimal_threshold).astype(int)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)

tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
fpr = fp / (fp + tn)

print(f"    AUC:                {test_auc:.4f}")
print(f"    Optimal threshold:  {optimal_threshold:.4f}")
print(f"    Precision:          {precision:.4f}")
print(f"    Recall:             {recall:.4f}")
print(f"    F1 Score:           {f1:.4f}")
print(f"    False Positive Rate:{fpr:.4f}")
print(f"    ")
print(f"    Confusion Matrix:")
print(f"      TP={tp:,} | FP={fp:,}")
print(f"      FN={fn:,} | TN={tn:,}")
print(f"    ")
print(f"    At threshold {optimal_threshold:.3f}:")
print(f"      Blocks {recall:.1%} of fraud")
print(f"      False positive rate: {fpr:.2%}")

# Feature importance
importance = final_model.feature_importance(importance_type="gain")
importance_sorted = sorted(zip(FEATURE_NAMES, importance), key=lambda x: -x[1])
print(f"\n    Feature Importance (gain):")
for feat, imp in importance_sorted:
    bar = "#" * int(imp / max(importance) * 30)
    print(f"      {feat:25s} {bar} {imp:.0f}")

# --- 6. Export ---
print("\n[6/6] Exporting model...")

# 6a. ONNX export
try:
    from onnxmltools import convert_lightgbm
    from onnxmltools.convert.common.data_types import FloatTensorType
    import onnx

    initial_type = [("features", FloatTensorType([None, len(FEATURE_NAMES)]))]
    onnx_model = convert_lightgbm(final_model, initial_types=initial_type)

    onnx_path = OUTPUT_DIR / "beans_shield_model.onnx"
    onnx.save_model(onnx_model, str(onnx_path))
    onnx_size = os.path.getsize(onnx_path)
    print(f"    ONNX saved: {onnx_path} ({onnx_size / 1024:.1f} KB)")
except Exception as e:
    print(f"    ONNX export failed: {e}")
    print(f"    (Continuing with JSON export)")

# 6b. JSON export (for ThresholdScorer)
json_config = {
    "model_version": "1.0.0",
    "trained_at": "2026-05-24",
    "feature_names": FEATURE_NAMES,
    "optimal_threshold": float(optimal_threshold),
    "metrics": {
        "auc": float(test_auc),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "false_positive_rate": float(fpr),
    },
    "feature_importance": {feat: float(imp) for feat, imp in importance_sorted},
    "threshold_scorer_config": {
        "description": "Simple threshold-based scorer for Go ThresholdScorer",
        "amount_threshold": 0.5,
        "velocity_threshold": 5.0,
        "weights": {feat: float(imp / sum(importance)) for feat, imp in importance_sorted},
    }
}

json_path = OUTPUT_DIR / "beans_shield_config.json"
with open(json_path, "w") as f:
    json.dump(json_config, f, indent=2)
print(f"    JSON saved: {json_path}")

# 6c. Save LightGBM native format
lgb_path = OUTPUT_DIR / "beans_shield_model.lgb"
final_model.save_model(str(lgb_path))
print(f"    LightGBM saved: {lgb_path}")

print("\n" + "=" * 60)
print("TRAINING COMPLETE")
print("=" * 60)
print(f"\nFiles in {OUTPUT_DIR}/:")
for f in sorted(OUTPUT_DIR.iterdir()):
    print(f"  - {f.name} ({os.path.getsize(f) / 1024:.1f} KB)")
