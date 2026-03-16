@echo off
echo Installing dependencies...
pip install -r requirements.txt

echo Generating data...
python utils/generate_data.py

echo Launching Dashboard...
streamlit run dashboard/app.py
pause
