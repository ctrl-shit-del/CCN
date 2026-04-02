"""
anomaly_detector.py
────────────────────────────────────────────────────────────────────────
ML-Based Behavioral Anomaly Detector  (PRD §8, Phase 3 Week 9-10)

Layer 3 defense — Isolation Forest trained only on normal provisioning
sessions.  No labelled attack data required (unsupervised).

PRD Feature Vector (5 features per session)
───────────────────────────────────────────
  F0  beacon_to_challenge_ms    – relay attack inflates this
  F1  challenge_to_response_ms  – relay attack inflates this
  F2  device_seen_before        – 0/1 flag, replay reuses same DeviceID
  F3  session_frequency         – attempts/min in a sliding window (DoS)
  F4  packet_size_variance      – tampered packets break expected sizes

Algorithm : IsolationForest (sklearn)
  contamination = 0.1  (assume ≤10 % of training data may be anomalous)
  random_state  = 42   (reproducible runs)
"""

from __future__ import annotations

import time
import math
import statistics
from collections import deque
from dataclasses import dataclass, astuple, field

import numpy as np
from sklearn.ensemble      import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline      import Pipeline
from sklearn.metrics       import classification_report, confusion_matrix


# ── Feature dataclass ──────────────────────────────────────────────────

@dataclass
class SessionFeatures:
    """Holds the 6 feature values for one provisioning session."""
    beacon_to_challenge_ms:   float   # F0
    challenge_to_response_ms: float   # F1
    device_seen_before:       int     # F2  0 = new device, 1 = repeated
    session_frequency:        float   # F3  sessions per minute (rolling)
    packet_size_variance:     float   # F4
    device_reuse_score:       float   # F5  = device_seen_before * session_frequency
                                      #     always 0 for legit sessions (large pool),
                                      #     4-10 for replay attackers who probe repeatedly

    # optional metadata — not fed to model
    label:     str = field(default="normal", compare=False)   # "normal" / "attack"
    attack_type: str = field(default="",     compare=False)

    def to_vector(self) -> list[float]:
        """Return the 6-element numeric feature vector."""
        return [
            self.beacon_to_challenge_ms,
            self.challenge_to_response_ms,
            float(self.device_seen_before),
            self.session_frequency,
            self.packet_size_variance,
            self.device_reuse_score,
        ]


# ── Feature extractor ──────────────────────────────────────────────────

class FeatureExtractor:
    """
    Maintains rolling state to compute session-level features from
    channel metrics and session history.

    Usage
    -----
        extractor = FeatureExtractor(window_seconds=60)
        ...
        feats = extractor.extract(device_id, channel_metrics, label="normal")
    """

    def __init__(self, window_seconds: float = 60.0):
        self._window   = window_seconds
        self._seen_ids: set[bytes]        = set()
        self._recent:   deque[float]      = deque()   # timestamps of recent sessions

    def extract(
        self,
        device_id:       bytes,
        channel_metrics: dict,
        label:           str = "normal",
        attack_type:     str = "",
    ) -> SessionFeatures:
        """Build a SessionFeatures from a completed session's channel metrics."""
        now = time.time()

        # F2 – device seen before
        seen = 1 if device_id in self._seen_ids else 0
        self._seen_ids.add(device_id)

        # F3 – session frequency: count sessions within the past window
        self._recent.append(now)
        cutoff = now - self._window
        while self._recent and self._recent[0] < cutoff:
            self._recent.popleft()
        frequency = len(self._recent) / (self._window / 60.0)  # per minute

        return SessionFeatures(
            beacon_to_challenge_ms   = channel_metrics.get("beacon_to_challenge_ms",   0.0),
            challenge_to_response_ms = channel_metrics.get("challenge_to_response_ms", 0.0),
            device_seen_before       = seen,
            session_frequency        = frequency,
            packet_size_variance     = channel_metrics.get("packet_size_variance",     0.0),
            device_reuse_score       = float(seen) * frequency,
            label                    = label,
            attack_type              = attack_type,
        )

    def reset(self):
        """Clear rolling state (call between training and evaluation runs)."""
        self._seen_ids.clear()
        self._recent.clear()


# ── Anomaly Detector ───────────────────────────────────────────────────

class AnomalyDetector:
    """
    Wraps an IsolationForest to detect anomalous provisioning sessions.

    Lifecycle
    ---------
    1.  Collect normal SessionFeatures via generate_normal_sessions().
    2.  Call train(features).
    3.  Call predict(features) or evaluate(features, true_labels).
    """

    CONTAMINATION = 0.10   # expect ~10% of training sessions to be tail outliers
    RANDOM_STATE  = 42

    def __init__(self):
        self._model: Pipeline | None = None

    # -- training ----------------------------------------------------------

    def train(self, normal_features: list[SessionFeatures]) -> None:
        """
        Fit a StandardScaler → IsolationForest pipeline on normal-session
        feature vectors.

        StandardScaler equalises all 5 features (including the binary
        device_seen_before) before the tree-based anomaly scorer runs,
        preventing high-range timing features from drowning out the flag.
        """
        X = np.array([f.to_vector() for f in normal_features], dtype=float)
        self._model = Pipeline([
            ("scaler", StandardScaler()),
            ("iso",    IsolationForest(
                contamination = self.CONTAMINATION,
                random_state  = self.RANDOM_STATE,
                n_estimators  = 200,
                max_samples   = "auto",
            )),
        ])
        self._model.fit(X)
        print(f"\n[ANOMALY] Model trained on {len(normal_features)} normal sessions.")
        print(f"[ANOMALY] Pipeline : StandardScaler -> IsolationForest "
              f"(n_estimators=200, contamination={self.CONTAMINATION})")  
        print(f"[ANOMALY] Features : beacon->challenge | challenge->response "
              f"| seen_before | freq/min | size_variance | reuse_score")

    # -- inference ---------------------------------------------------------

    def predict(self, features: list[SessionFeatures]) -> list[str]:
        """
        Returns list of "normal" / "anomaly" for each session.
        IsolationForest returns +1 (inlier) → "normal", -1 (outlier) → "anomaly".
        """
        if self._model is None:
            raise RuntimeError("Call train() before predict().")
        X = np.array([f.to_vector() for f in features], dtype=float)
        raw = self._model.predict(X)          # +1 (inlier) or -1 (outlier)
        return ["normal" if r == 1 else "anomaly" for r in raw]

    def anomaly_scores(self, features: list[SessionFeatures]) -> list[float]:
        """
        Return raw anomaly scores (lower = more anomalous).
        The pipeline applies StandardScaler before scoring.
        """
        if self._model is None:
            raise RuntimeError("Call train() before anomaly_scores().")
        X = np.array([f.to_vector() for f in features], dtype=float)
        return list(self._model.score_samples(X))

    # -- evaluation --------------------------------------------------------

    def evaluate(
        self,
        test_features:  list[SessionFeatures],
        print_report:   bool = True,
    ) -> dict:
        """
        Predict on test_features (which carry .label = 'normal'/'attack')
        and return accuracy, false-positive rate, and a full sklearn report.
        """
        predictions  = self.predict(test_features)
        true_labels  = ["anomaly" if f.label == "attack" else "normal"
                        for f in test_features]

        n_total     = len(predictions)
        n_correct   = sum(p == t for p, t in zip(predictions, true_labels))
        accuracy    = n_correct / n_total if n_total else 0

        # false positives: normal session flagged as anomaly
        fp = sum(p == "anomaly" and t == "normal"
                 for p, t in zip(predictions, true_labels))
        n_normal    = sum(t == "normal" for t in true_labels)
        fpr         = fp / n_normal if n_normal else 0

        if print_report:
            print("\n" + "─" * 56)
            print("  ML ANOMALY DETECTION EVALUATION REPORT")
            print("─" * 56)
            print(f"  Total sessions evaluated : {n_total}")
            print(f"  Accuracy                 : {accuracy:.1%}")
            print(f"  False Positive Rate      : {fpr:.1%}")
            print()
            print("  Per-class breakdown:")
            labels_order = ["normal", "anomaly"]
            for i, feat in enumerate(test_features):
                pred = predictions[i]
                true = true_labels[i]
                match = "✓" if pred == true else "✗"
                print(f"    [{match}] {feat.attack_type or feat.label:<18} "
                      f"true={true:<8} pred={pred}")
            print()
            try:
                print(classification_report(
                    true_labels, predictions, target_names=labels_order, zero_division=0
                ))
            except Exception:
                pass
            print("─" * 56)

        return {
            "accuracy":            accuracy,
            "false_positive_rate": fpr,
            "predictions":         predictions,
            "true_labels":         true_labels,
        }


# ── Normal-session generator (for training data) ───────────────────────

def generate_normal_sessions(n: int = 100, seed: int = 0) -> list[SessionFeatures]:
    """
    Simulate n normal provisioning sessions with realistic timing jitter.

    Normal timing profile (from PRD NFR-2: < 500 ms per session):
      beacon→challenge  :  0 – 40 ms   (local in-process channel)
      challenge→response:  0 – 30 ms
      packet_size_variance: ~small (all packets are fixed-format)
    """
    rng = __import__("random")
    rng.seed(seed)
    sessions: list[SessionFeatures] = []
    seen_ids: set[int] = set()

    for i in range(n):
        # Pool of 2 000 IDs with 200 training sessions.
        # Expected repeats ~ 200*199/2/2000 = 10 — this gives device_reuse_score
        # a small but non-zero variance in training so IsolationForest can learn
        # the boundary.  Normal repeat freq is capped at 4/min, replay attackers
        # always exceed 5/min keeping the decision boundary clean.
        dev_id = rng.randint(1, 2_000)
        seen   = 1 if dev_id in seen_ids else 0
        seen_ids.add(dev_id)
        freq   = rng.uniform(0.5, 4.0)

        sessions.append(SessionFeatures(
            beacon_to_challenge_ms   = rng.uniform(0.5,  15.0),
            challenge_to_response_ms = rng.uniform(0.5,  10.0),
            device_seen_before       = seen,
            session_frequency        = freq,
            packet_size_variance     = rng.uniform(0.0,   4.0),
            device_reuse_score       = float(seen) * freq,   # 0 or 0.5-4 (rare)
            label                    = "normal",
            attack_type              = "normal",
        ))
    return sessions


def generate_attack_sessions(seed: int = 99) -> list[SessionFeatures]:
    """
    Generate labelled attack sessions showing distinct feature signatures.

    Replay attack    – same DeviceID reused, timing similar to normal
    Relay attack     – significantly higher beacon→challenge & challenge→response delays
    Misbinding attack– different DeviceID in response; high frequency probing
    DoS              – very high session frequency
    """
    rng = __import__("random")
    rng.seed(seed)
    sessions: list[SessionFeatures] = []

    # -- Replay attacks ---------------------------------------------------
    # device_seen_before=1 AND device_reuse_score = freq (5-12).
    # Normal training max device_reuse_score ~ 4 → attack values (5-12) are
    # clearly outside training range and isolated in very few splits.
    for _ in range(15):
        freq = rng.uniform(5.0, 12.0)   # strictly above normal max (4.0)
        sessions.append(SessionFeatures(
            beacon_to_challenge_ms   = rng.uniform(1.0, 20.0),
            challenge_to_response_ms = rng.uniform(1.0, 15.0),
            device_seen_before       = 1,
            session_frequency        = freq,
            packet_size_variance     = rng.uniform(0.0,  4.0),
            device_reuse_score       = 1.0 * freq,   # 5-12: above training max of ~4
            label                    = "attack",
            attack_type              = "replay",
        ))

    # ── Relay attacks ─────────────────────────────────────────────────
    for _ in range(15):
        sessions.append(SessionFeatures(
            beacon_to_challenge_ms   = rng.uniform(120.0, 400.0),  # high delay
            challenge_to_response_ms = rng.uniform(100.0, 350.0),  # high delay
            device_seen_before       = rng.randint(0, 1),
            session_frequency        = rng.uniform(0.5,  3.0),
            packet_size_variance     = rng.uniform(0.0,  6.0),
            device_reuse_score       = 0.0,
            label                    = "attack",
            attack_type              = "relay",
        ))

    # ── Misbinding attacks ────────────────────────────────────────────
    for _ in range(10):
        sessions.append(SessionFeatures(
            beacon_to_challenge_ms   = rng.uniform(1.0,  20.0),
            challenge_to_response_ms = rng.uniform(1.0,  15.0),
            device_seen_before       = 0,
            session_frequency        = rng.uniform(8.0,  20.0),    # probing
            packet_size_variance     = rng.uniform(8.0,  20.0),    # tampered fields
            device_reuse_score       = 0.0,
            label                    = "attack",
            attack_type              = "misbinding",
        ))

    # ── DoS / brute-force ─────────────────────────────────────────────
    for _ in range(10):
        seen_dos = rng.randint(0, 1)
        freq_dos = rng.uniform(50.0, 150.0)
        sessions.append(SessionFeatures(
            beacon_to_challenge_ms   = rng.uniform(0.5, 10.0),
            challenge_to_response_ms = rng.uniform(0.5,  8.0),
            device_seen_before       = seen_dos,
            session_frequency        = freq_dos,           # very high
            packet_size_variance     = rng.uniform(0.0,   5.0),
            device_reuse_score       = float(seen_dos) * freq_dos,
            label                    = "attack",
            attack_type              = "DoS",
        ))

    return sessions
