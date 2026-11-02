import requests

url = "http://127.0.0.1:8080/graphql"

# Login as guest
m = "mutation { loginAsGuest { token { accessToken } } }"
r = requests.post(url, json={"query": m})
token = r.json()["data"]["loginAsGuest"]["token"]["accessToken"]

headers = {"Authorization": f"Bearer {token}"}

q = """
query {
  projects {
    edges {
      node {
        id
        name
      }
    }
  }
  currentProject {
    id
    name
  }
}
"""
r2 = requests.post(url, json={"query": q}, headers=headers)
print("Projects:", r2.json())

