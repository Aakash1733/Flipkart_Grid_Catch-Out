import requests

url = "https://www.codegrepper.com/profile/stefano-romeo"

r = requests.get(url)
with open('file.html', 'w') as file:
    file.write(r.text)
