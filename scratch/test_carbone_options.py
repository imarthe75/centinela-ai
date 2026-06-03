import requests

html_content = """
<html>
<head>
    <style>
        body { font-family: Arial; }
    </style>
</head>
<body>
    <h1>Hello World</h1>
</body>
</html>
"""

# Test 1: Just extension html
p1 = {
    "template": html_content,
    "data": {},
    "convertTo": "pdf",
    "options": {
        "extension": "html"
    }
}
res1 = requests.post("http://casmarts-core-carbone/render/template", json=p1)
print("Test 1 (extension: html):", res1.status_code, res1.text)

# Test 2: extension html + delimiters
p2 = {
    "template": html_content,
    "data": {},
    "convertTo": "pdf",
    "options": {
        "extension": "html",
        "delimiters": "[[ ]]"
    }
}
res2 = requests.post("http://casmarts-core-carbone/render/template", json=p2)
print("Test 2 (extension: html + delimiters):", res2.status_code, res2.text)
