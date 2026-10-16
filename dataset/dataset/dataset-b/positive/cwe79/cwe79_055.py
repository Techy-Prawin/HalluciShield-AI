from flask import Flask, request

app = Flask(__name__)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    html = f'<html><body><h1>Search Results for {query}</h1></body></html>'
    return html

if __name__ == '__main__':
    app.run()