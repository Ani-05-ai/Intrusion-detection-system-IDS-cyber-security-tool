from flask import Flask
from app.routes import bp as detection_bp

app = Flask(__name__)
app.register_blueprint(detection_bp)

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True, port=5000)