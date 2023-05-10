import requests
import os

# Auth proxy setting
ca_cert_path = os.path.join(os.getcwd(), os.pardir, os.pardir, "proxy", "certs", "ca_cert.pem")
proxies = {'https': 'http://127.0.0.1:9999', 'http': 'http://127.0.0.1:9999'}

if __name__ == "__main__":
  s = requests.Session()
  response = s.get(
      f'https://pubsub.mtls.googleapis.com/v1/projects/sijunliu-dca-test/topics',
      proxies=proxies,
      verify=ca_cert_path, 
  )
  print(response.text)