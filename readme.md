---

# AIS-Based Cyber Threat Detection System

An **Artificial Immune System (AIS)** for real-time anomaly detection in time-series data, built using the **Numenta Anomaly Benchmark (NAB)** dataset. This system leverages biologically inspired algorithms — **Negative Selection (NSA)** and **Clonal Selection (CSA)** — and features a responsive **Streamlit web interface** with dynamic visualizations powered by Plotly.

📊 **Model Performance**

* **Accuracy**: 92%
* **Precision**: 90%
* **Recall**: 88%
* **F1-Score**: 89%
* **ROC-AUC**: 93%

---

## 🎯 Key Features

* **AIS-Powered Detection**: Detects anomalies in NAB time-series data using NSA and CSA.
* **Real-Time Monitoring**: Adjustable detection threshold via intuitive slider (0.1–1.0).
* **Interactive Dashboard**: Gradient headers, navy-themed sidebar, coral highlights, and Plotly charts.
* **Dynamic Visuals**: ROC curves (coral), confusion matrices (blue), and anomaly tables.
* **Metric Cards**: Real-time display of performance metrics like Accuracy, F1, and AUC.
* **Preprocessing Pipeline**: Time-series feature engineering (rolling stats, differences).

---

## 📁 Project Structure

```
Artificial-Immune-System--AIS--based-cyber-threat-detection/
├── ais_model.py            # Core NSA/CSA algorithms
├── train_ais_nab.py        # Model training script
├── app.py                  # Streamlit interface
├── data/
│   ├── realKnownCause/
│   │   └── nyc_taxi.csv
│   └── labels/
│       └── combined_labels.json
├── models/
│   └── ais_nab_model.pkl   # Trained AIS model
├── requirements.txt        # Dependencies
└── README.md               # Documentation
```

---

## 🧰 Installation

### 1. Clone Repository

```bash
git clone https://github.com/Akobabs/Artificial-Immune-System--AIS--based-cyber-threat-detection.git
cd Artificial-Immune-System--AIS--based-cyber-threat-detection
```

### 2. Create Virtual Environment

```bash
python -m venv venv
venv\Scripts\activate  # Windows
# Or: source venv/bin/activate  # macOS/Linux
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 📦 Dataset Setup

1. Download the NAB dataset:

   * GitHub: [https://github.com/numenta/NAB](https://github.com/numenta/NAB)
   * Kaggle: \[Search NAB Dataset]

2. Organize data folders:

```
data/
├── realKnownCause/
│   └── nyc_taxi.csv
└── labels/
    └── combined_labels.json
```

---

## 🚀 Usage

### 1. Train the AIS Model

```bash
python train_ais_nab.py
```

* Outputs the model at `models/ais_nab_model.pkl`.
* Displays evaluation metrics in the console.

### 2. Launch the Web Interface

```bash
streamlit run app.py
```

* Access the app at: [http://localhost:8501](http://localhost:8501)

---

## 🧪 How to Use the App

* **Home**: View overview, metrics, and model info.
* **Upload & Analyze**:

  * Upload `nyc_taxi.csv` and optionally `combined_labels.json`.
  * Adjust threshold using the sidebar.
  * View ROC curve, confusion matrix, anomaly alerts.
* **About**: Project background and future roadmap.

---

## 🛠 Troubleshooting

| Issue                    | Solution                                            |
| ------------------------ | --------------------------------------------------- |
| `Model not found`        | Run `python train_ais_nab.py`                       |
| `Missing columns in CSV` | Ensure the file has `timestamp` and `value` columns |
| `Label loading failed`   | Verify `combined_labels.json` format and path       |
| Missing dependencies     | Run `pip install -r requirements.txt`               |

---

## 🔭 Future Work

* **Fourier Features**:

  ```python
  from scipy.fft import fft
  df['fft'] = np.abs(fft(df['value']))[:len(df)//2]
  ```
* **Higher Detector Count**: For broader anomaly coverage.
* **Kafka Integration**: For real-time streaming data input.
* **AWS Deployment**: Cloud hosting and scalability.
* **Advanced AIS Models**: Explore Artificial Immune Networks (AIN).

---

## 📊 Dataset Overview

* **Source**: Numenta Anomaly Benchmark (NAB)
* **Format**: CSV files with timestamps and values
* **Example**: `nyc_taxi.csv` shows taxi volume anomalies
* **Labels**: JSON format with timestamped anomaly markers

---

## 🙏 Acknowledgments

* **Numenta** for the NAB dataset
* **Streamlit** for powering the UI
* **Benson Idahosa University, Benin, Edo State** for academic guidance

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 📬 Contact

Created by [Akobabs](https://github.com/Akobabs)
🔧 Raise issues or pull requests via the [GitHub Issues tab](https://github.com/Akobabs/Artificial-Immune-System--AIS--based-cyber-threat-detection/issues)

