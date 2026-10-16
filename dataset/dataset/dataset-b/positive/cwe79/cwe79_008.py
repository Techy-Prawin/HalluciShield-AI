from flask import Flask, request, Response

app = Flask(__name__)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Vulnerable: directly injecting user input into HTML
    html = f"<html><body><h1>Results for: {query}</h1></body></html>"
    return Response(html, mimetype='text/html')