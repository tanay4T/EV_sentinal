import os
import json
import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, OneHotEncoder, LabelEncoder
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix


DATA_PATH = "cic_evse_2024_merged.csv"
MODEL_DIR = "generalized_telematics_model"
MODEL_PATH = os.path.join(MODEL_DIR, "generalized_bundle.joblib")
os.makedirs(MODEL_DIR, exist_ok=True)


def get_feature_columns(df: pd.DataFrame):
    # Core features only — no engineered features
    preferred_features = [
        "bidirectional_duration_ms",
        "bidirectional_packets",
        "bidirectional_bytes",
        "src2dst_packets",
        "src2dst_bytes",
        "dst2src_packets",
        "dst2src_bytes",
        "bidirectional_mean_ps",
        "bidirectional_stddev_ps",
        "protocol",
        "packet_rate_pps",
        "byte_rate_bps",
        "src2dst_packet_ratio",
        "src2dst_byte_ratio",
        "bytes_per_packet",
        "flow_duration_sec",
        "frequency_category"
    ]
    return [col for col in preferred_features if col in df.columns]


def build_preprocessor(X: pd.DataFrame):
    numeric_cols = X.select_dtypes(include=["number"]).columns.tolist()
    categorical_cols = X.select_dtypes(include=["object", "category", "bool"]).columns.tolist()

    numeric_pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler())
    ])

    categorical_pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="most_frequent")),
        ("encoder", OneHotEncoder(handle_unknown="ignore"))
    ])

    preprocessor = ColumnTransformer([
        ("num", numeric_pipeline, numeric_cols),
        ("cat", categorical_pipeline, categorical_cols)
    ])

    return preprocessor


def compute_severity(predicted_label: str, confidence: float, anomaly_score: float, anomaly_threshold: float) -> str:
    is_anomalous = anomaly_score < anomaly_threshold
    label = str(predicted_label).lower()

    if label == "benign" and not is_anomalous:
        return "Low"

    if label in ["backdoor", "cryptojacking"]:
        return "Critical" if confidence >= 0.70 or is_anomalous else "High"

    if label == "flood-attack":
        return "High" if confidence >= 0.65 or is_anomalous else "Medium"

    if label == "scan-probe":
        return "High" if is_anomalous else "Medium"

    if is_anomalous and confidence < 0.50:
        return "Critical"

    return "Medium"


def mild_perturbation(df: pd.DataFrame, random_state=42):
    rng = np.random.default_rng(random_state)
    perturbed = df.copy()

    numeric_cols = perturbed.select_dtypes(include=["number"]).columns.tolist()

    # very mild 0.5% noise only
    for col in numeric_cols:
        noise = rng.normal(0, 0.005, size=len(perturbed))
        perturbed[col] = perturbed[col] * (1 + noise)

    return perturbed


def train_model():
    # print("Loading dataset...")
    df = pd.read_csv(DATA_PATH)

    feature_cols = get_feature_columns(df)
    X = df[feature_cols].copy()
    y = df["label"].astype(str)

    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)

    # print("Creating 60/15/25 split...")
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y_encoded,
        test_size=0.40,
        stratify=y_encoded,
        random_state=42
    )

    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp,
        test_size=0.625,   # 25 overall test, 15 overall val
        stratify=y_temp,
        random_state=42
    )

    preprocessor = build_preprocessor(X_train)

    # Simple regularized classifier
    clf = LogisticRegression(
        C=0.5,
        max_iter=2000,
        class_weight="balanced",
        random_state=42
    )

    clf_pipeline = Pipeline([
        ("preprocessor", preprocessor),
        ("classifier", clf)
    ])

    # print("Training Logistic Regression...")
    clf_pipeline.fit(X_train, y_train)

    print("\n========== VALIDATION RESULTS ==========")
    y_val_pred = clf_pipeline.predict(X_val)
    print("Validation Accuracy:", round(accuracy_score(y_val, y_val_pred), 4))
    print(classification_report(
        label_encoder.inverse_transform(y_val),
        label_encoder.inverse_transform(y_val_pred)
    ))

    print("\n========== TEST RESULTS ==========")
    y_test_pred = clf_pipeline.predict(X_test)
    print("Test Accuracy:", round(accuracy_score(y_test, y_test_pred), 4))
    print(classification_report(
        label_encoder.inverse_transform(y_test),
        label_encoder.inverse_transform(y_test_pred)
    ))
    print("Confusion Matrix:")
    print(confusion_matrix(
        label_encoder.inverse_transform(y_test),
        label_encoder.inverse_transform(y_test_pred),
        labels=label_encoder.classes_
    ))

    # print("\nTraining Isolation Forest on benign train rows...")
    benign_encoded = label_encoder.transform(["benign"])[0]
    X_train_benign = X_train[y_train == benign_encoded].copy()

    anomaly_preprocessor = build_preprocessor(X_train_benign)
    X_train_benign_processed = anomaly_preprocessor.fit_transform(X_train_benign)

    anomaly_model = IsolationForest(
        n_estimators=150,
        contamination=0.05,
        random_state=42,
        n_jobs=-1
    )
    anomaly_model.fit(X_train_benign_processed)

    benign_scores = anomaly_model.decision_function(X_train_benign_processed)
    anomaly_threshold = float(np.percentile(benign_scores, 5))
    # print("Anomaly threshold:", round(anomaly_threshold, 4))

    # robustness check on mildly perturbed unseen test rows
    # print("\n========== ROBUSTNESS CHECK (MILDLY PERTURBED TEST ROWS) ==========")
    X_test_perturbed = mild_perturbation(X_test, random_state=42)
    y_test_perturbed_pred = clf_pipeline.predict(X_test_perturbed)
    robustness_acc = accuracy_score(y_test, y_test_perturbed_pred)
    # print("Perturbed Test Accuracy:", round(robustness_acc, 4))

    bundle = {
        "classifier_pipeline": clf_pipeline,
        "anomaly_preprocessor": anomaly_preprocessor,
        "anomaly_model": anomaly_model,
        "anomaly_threshold": anomaly_threshold,
        "feature_columns": feature_cols,
        "label_encoder": label_encoder,
        "X_test": X_test,
        "y_test": y_test,
        "X_val": X_val,
        "y_val": y_val
    }

    joblib.dump(bundle, MODEL_PATH)
    # print(f"\nSaved model at: {MODEL_PATH}")


def load_bundle():
    return joblib.load(MODEL_PATH)


def predict_telematics_event(event: dict):
    bundle = load_bundle()

    clf_pipeline = bundle["classifier_pipeline"]
    anomaly_preprocessor = bundle["anomaly_preprocessor"]
    anomaly_model = bundle["anomaly_model"]
    anomaly_threshold = bundle["anomaly_threshold"]
    feature_cols = bundle["feature_columns"]
    label_encoder = bundle["label_encoder"]

    sample_df = pd.DataFrame([event])

    for col in feature_cols:
        if col not in sample_df.columns:
            sample_df[col] = np.nan

    sample_df = sample_df[feature_cols]

    prob_array = clf_pipeline.predict_proba(sample_df)[0]
    pred_encoded = int(np.argmax(prob_array))
    pred_label = label_encoder.inverse_transform([pred_encoded])[0]
    confidence = float(np.max(prob_array))

    processed_sample = anomaly_preprocessor.transform(sample_df)
    anomaly_score = float(anomaly_model.decision_function(processed_sample)[0])
    is_anomalous = anomaly_score < anomaly_threshold

    if is_anomalous and confidence < 0.50:
        final_decision = "Novel Threat / Suspicious Anomaly"
    else:
        final_decision = pred_label

    severity = compute_severity(
        predicted_label=final_decision,
        confidence=confidence,
        anomaly_score=anomaly_score,
        anomaly_threshold=anomaly_threshold
    )

    return {
        "predicted_label": str(pred_label),
        "classifier_confidence": round(confidence, 4),
        "anomaly_score": round(anomaly_score, 4),
        "anomaly_threshold": round(anomaly_threshold, 4),
        "is_anomalous": bool(is_anomalous),
        "final_decision": str(final_decision),
        "severity": severity
    }


def inference_on_unseen_rows(samples_per_class=1):
    bundle = load_bundle()
    X_test = bundle["X_test"].copy()
    y_test = bundle["y_test"]
    label_encoder = bundle["label_encoder"]

    y_test_labels = label_encoder.inverse_transform(y_test)
    test_df = X_test.copy()
    test_df["actual_label"] = y_test_labels

    print("\n========== INFERENCE ON UNSEEN TEST ROWS ==========")

    for label in label_encoder.classes_:
        rows = test_df[test_df["actual_label"] == label].head(samples_per_class)

        print(f"\n===== ACTUAL LABEL: {label} =====")
        for _, row in rows.iterrows():
            event = row.drop("actual_label").to_dict()
            result = predict_telematics_event(event)
            print(json.dumps(result, indent=4))


if __name__ == "__main__":
    train_model()
    # inference_on_unseen_rows(samples_per_class=1)