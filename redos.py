# This is a python script that makes a single http request to a web server

import requests
import sys

# This is the main function
def main():
    url = "http://"+sys.argv[1]
    iterations = int(sys.argv[2])
    print("URL: " + url)
    headers = {'User-Agent': 'android0/ Barnes&Noble '+ ' '*iterations + '!'} 
    r = requests.get(url, headers=headers)
    print(r.text)

main()