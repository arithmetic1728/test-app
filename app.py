from google.auth.transport.requests import AuthorizedSession
import google.auth

credentials, _ = google.auth.default()
project = "sijunliu-nondca-test"

if __name__ == "__main__":
    authed_session = AuthorizedSession(credentials)
    response = authed_session.request('GET', f'https://pubsub.googleapis.com/v1/projects/{project}/topics')
    print(response.status_code)