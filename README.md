# DeepShield AI

Edge-Based Deep Learning Malware Detection for Automotive Cybersecurity.

## Login

- Username: `engineer`
- Password: `deepshield123`

## Run Flask Website

```bash
pip install -r requirements.txt
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

## Run Streamlit Dashboard

```bash
streamlit run streamlit_dashboard.py
```

## Pages Included

- Login
- Dashboard
- Upload and scan
- Result page
- Scan history
- Downloadable report
- Logout
- Thank-you page

## Notes

The project includes a runnable deep-learning-style classifier. If you later train
a real TensorFlow/Keras model, place it at `models/deepshield_model.h5` and extend
the feature vector as needed.
