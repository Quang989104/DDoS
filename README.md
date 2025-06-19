# DDoS Attack Detection Software

##  Introduction

This is a **DDoS (Distributed Denial of Service)** attack detection software developed as part of a course project.  
The system utilizes packet analysis and network traffic inspection techniques to detect abnormal behavior caused by DDoS attacks.

##  Objectives

- Capture and process network traffic data
- Apply threshold-based analysis techniques to detect DDoS attacks
- Classify DoS and DDoS attacks
- Provide a user-friendly interface for real-time traffic monitoring and alerting
- Scalable and suitable for integration into real network environments

## ⚙️ Technologies Used

| Component         | Technologies                        |
|-------------------|-------------------------------------|
| Programming Languages | Python, JavaScript             |
| Front-end Interface   | HTML, CSS                      |
| Packet Capturing      | Scapy, Tshark, NCAP            |
| Database              | SQLite3                        |
| Data Visualization    | Chart.js (JavaScript), Plotly (Python) |

##  Setup Instructions

1. Install the required libraries:  
   `pip install -r requirements.txt`

2. Install NCAP

3. Start the FastAPI server:  
   `uvicorn app:app --reload`

4. Open the web interface:  
   `http://127.0.0.1:8000/`

5. Login with default credentials:
Username: Admin
Password: 123
6. Run the packet analysis script:  
`python detect_ddos.py`

## 🖼️ DEMO: Software Interface

![Login Interface](static/assets/Login.png)  
![Main Interface](static/assets/Main.png)  
![Alert Interface](static/assets/Alert.png)  
![Report Interface](static/assets/Report.png)  
![Setting Interface](static/assets/Setting.png)  
![Gmail Alert](static/assets/gmail.png)

## 📝 License

MIT License

Copyright (c) 2025 [Quang989104]

Permission is hereby granted, free of charge, to any person obtaining a copy  
of this software and associated documentation files (the "Software"), to deal  
in the Software without restriction, including without limitation the rights to  
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies  
of the Software, and to permit persons to whom the Software is furnished to do  
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all  
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,  
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE  
AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,  
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,  
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
