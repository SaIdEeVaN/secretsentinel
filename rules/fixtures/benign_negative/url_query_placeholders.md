# Placeholders and look-alikes that must NOT be reported

- https://api.example.test/v1/items?api_key=YOUR_API_KEY&limit=10
- https://api.example.test/v1/items?token=${TOKEN}&limit=10
- https://api.example.test/v1/items?token=<your-token-goes-here>&limit=10
- https://api.example.test/v1/items?access_token=aaaaaaaaaaaaaaaaaaaaaaaaaaaa&limit=10
- https://api.example.test/v1/items?page_token=CAESBwgBEAEYAxgCIAE&limit=10
- https://api.example.test/v1/items?api_key=short&limit=10
