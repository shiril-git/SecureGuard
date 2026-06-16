import requests
import json

# Test URL (use a test site or your own)
test_url = "https://example.com"

response = requests.post(
    'http://localhost:5000/api/scan/admin-panel',
    json={'url': test_url}
)

print(json.dumps(response.json(), indent=2))