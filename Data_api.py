from flask import Flask, Response
import pandas as pd

app = Flask(__name__)

data = {
    "ThreatID": range(1, 10001),  
    "ThreatScore": [round(x % 10 * 0.1, 2) for x in range(1, 10001)]
}

df = pd.DataFrame(data)

@app.route('/threat_data', methods=['GET'])
def get_csv():
    csv_data = df.to_csv(index=False)
    return Response(csv_data, mimetype="text/csv")

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
