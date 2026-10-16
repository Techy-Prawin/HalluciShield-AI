from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    template = f'<html><body><h1>Search Results for: {query}</h1></body></html>'
    return render_template_string(template)

if __name__ == '__main__':
    app.run(debug=True)