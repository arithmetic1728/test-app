from google.auth.transport.requests import AuthorizedSession
import google.auth

credentials, _ = google.auth.default()
project = "sijunliu-nondca-test"

proxies = {
  'http': 'http://127.0.0.1:9999',
  'https': 'http://127.0.0.1:9999',
}

if __name__ == "__main__":
    authed_session = AuthorizedSession(credentials)
    response = authed_session.request(
        'GET',
        f'https://pubsub.googleapis.com/v1/projects/{project}/topics',
        proxies=proxies,
        verify=False
    )
    print(response.status_code)