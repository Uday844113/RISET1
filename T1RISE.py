import re
import pandas as pd
import tkinter as tk
from tkinter import messagebox, filedialog
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib
import os

MODEL_FILE = "phishing_model.pkl"

# === Feature Engineering ===
def extract_features(url):
    return {
        'url_length': len(url),
        'dot_count': url.count('.'),
        'contains_https': int('https' in url),
        'contains_ip': int(bool(re.match(r"http://\d{1,3}(\.\d{1,3}){3}", url))),
        'has_suspicious_words': int(any(word in url.lower() for word in ['login', 'secure', 'account', 'update', 'verify']))
    }

# === Train and Save Model if Not Exists ===
def train_model():
    if os.path.exists(MODEL_FILE):
        return joblib.load(MODEL_FILE)

    df = pd.read_csv("urls.csv")
    df_features = df['url'].apply(extract_features).apply(pd.Series)
    X = df_features
    y = df['label']
    
    model = RandomForestClassifier()
    model.fit(X, y)
    
    joblib.dump(model, MODEL_FILE)
    print("Model trained and saved.")
    return model

model = train_model()

# === ML Prediction ===
def predict_url_ml(url):
    features = pd.DataFrame([extract_features(url)])
    return model.predict(features)[0]

# === GUI Logic ===
def check_single_url():
    url = entry.get()
    if not url:
        messagebox.showinfo("Info", "Please enter a URL.")
        return
    
    ml_result = predict_url_ml(url)
    
    if ml_result == 1:
        messagebox.showwarning("⚠️ ML Alert", f"The URL:\n{url}\nis predicted as **Phishing**!")
    else:
        messagebox.showinfo("✅ ML Safe", f"The URL:\n{url}\nis predicted as **Safe**.")

def batch_check():
    file_path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
    if not file_path:
        return
    try:
        df = pd.read_csv(file_path)
        if 'url' not in df.columns:
            messagebox.showerror("Error", "CSV must contain a 'url' column.")
            return
        df['features'] = df['url'].apply(extract_features)
        features_df = df['features'].apply(pd.Series)
        df['ml_prediction'] = model.predict(features_df)
        result_file = "ml_batch_results.csv"
        df.to_csv(result_file, index=False)
        messagebox.showinfo("Done", f"Batch ML check complete.\nSaved to {result_file}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to process file:\n{e}")

# === GUI Layout ===
root = tk.Tk()
root.title("Phishing URL Detection Tool (with ML)")
root.geometry("500x300")

tk.Label(root, text="Enter a URL to check:", font=("Arial", 12)).pack(pady=10)
entry = tk.Entry(root, width=60)
entry.pack(pady=5)

tk.Button(root, text="Check URL with ML", command=check_single_url, bg="lightblue").pack(pady=5)
tk.Button(root, text="Batch Check (CSV via ML)", command=batch_check, bg="lightgreen").pack(pady=5)

tk.Label(root, text="ML Phishing Detector © 2025", font=("Arial", 9)).pack(side="bottom", pady=10)

root.mainloop()

