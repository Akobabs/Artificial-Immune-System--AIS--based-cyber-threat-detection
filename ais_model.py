import numpy as np

class NegativeSelectionAlgorithm:
    def __init__(self, detector_count=100, threshold=0.5):
        self.detector_count = detector_count
        self.threshold = threshold
        self.detectors = []

    def generate_detectors(self, self_data, feature_count):
        """Generate detectors that do not match self patterns."""
        while len(self.detectors) < self.detector_count:
            detector = np.random.rand(feature_count)
            if not self._matches_self(detector, self_data):
                self.detectors.append(detector)

    def _matches_self(self, detector, self_data):
        """Check if detector matches any self pattern."""
        for self_pattern in self_data:
            distance = np.linalg.norm(detector - self_pattern)
            if distance < self.threshold:
                return True
        return False

    def detect_anomalies(self, data):
        """Detect anomalies in new data."""
        anomalies = []
        for pattern in data:
            is_anomaly = any(np.linalg.norm(detector - pattern) < self.threshold for detector in self.detectors)
            anomalies.append(is_anomaly)
        return np.array(anomalies)

class ClonalSelectionAlgorithm:
    def __init__(self, clone_factor=0.1, mutation_rate=0.01):
        self.clone_factor = clone_factor
        self.mutation_rate = mutation_rate

    def refine_detectors(self, detectors, data, labels):
        """Refine detectors using clonal selection."""
        refined_detectors = []
        for detector in detectors:
            clones = self._clone_detector(detector, data, labels)
            for clone in clones:
                if np.random.random() < self.mutation_rate:
                    clone += np.random.normal(0, 0.1, len(clone))
                refined_detectors.append(clone)
        return refined_detectors[:len(detectors)]

    def _clone_detector(self, detector, data, labels):
        """Clone detector based on affinity."""
        affinity = self._calculate_affinity(detector, data, labels)
        clone_count = int(self.clone_factor * affinity)
        return [detector.copy() for _ in range(max(1, clone_count))]

    def _calculate_affinity(self, detector, data, labels):
        """Calculate detector affinity based on correct detections."""
        matches = sum(1 for i, pattern in enumerate(data) if np.linalg.norm(detector - pattern) < 0.5 and labels[i])
        return matches