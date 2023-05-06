from google.auth.transport.requests import AuthorizedSession
import google.auth
import os

credentials, _ = google.auth.default()
project = "sijunliu-dca-test"

proxies = {
  'http': 'http://127.0.0.1:9999',
  'https': 'http://127.0.0.1:9999',
}

ca_cert_path = os.path.join(os.getcwd(), os.pardir, "proxy", "certs", "ca_cert.pem")

def run_with_https(stream=False):
  authed_session = AuthorizedSession(credentials)
  response = authed_session.request(
      'GET',
      f'https://pubsub.mtls.googleapis.com/v1/projects/{project}/topics',
      proxies=proxies,
      verify=ca_cert_path,
      stream=stream
  )
  if stream:
    for line in response.iter_lines():
      if line:
          print(line)
  else:
    print(response.text)

if __name__ == "__main__":
  run_with_https()
  run_with_https(stream=True)