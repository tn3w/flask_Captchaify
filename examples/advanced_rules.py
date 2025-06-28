from flask import Flask, request, jsonify
from flask_humanify import Humanify

# Create Flask application
app = Flask(__name__)
app.config["SECRET_KEY"] = "your-secret-key"

# Initialize Humanify
humanify = Humanify(app, challenge_type="one_click", image_dataset="ai_dogs")

# Example 1: Protect API endpoints with regex pattern
humanify.register_middleware(
    action="challenge",
    endpoint_patterns=[
        "api\\..*"
    ],  # Matches any route with endpoint starting with "api."
)

# Example 2: Protect admin routes with URL pattern and deny access
humanify.register_middleware(
    action="deny_access",
    url_patterns=[
        "/admin/*",
        "/settings/*",
    ],  # Protects URLs starting with /admin/ or /settings/
)

# Example 3: Protect write operations on sensitive endpoints, but exclude health check
humanify.register_middleware(
    endpoint_patterns=["sensitive\\..*"],
    exclude_patterns=["sensitive\\.health"],
    request_filters={"method": ["POST", "PUT", "DELETE"]},
)

# Example 4: Complex filtering with query parameters and headers
humanify.register_middleware(
    endpoint_patterns=["data\\..*"],
    request_filters={
        "args.access_level": [
            "premium",
            "admin",
        ],  # Only when access_level parameter is premium or admin
        "headers.content-type": "regex:application/json.*",  # Only JSON requests
        "json.operation": "write",  # Only when the JSON body has operation: write
    },
)


# Define some example routes
@app.route("/")
def index():
    return "Public homepage - no protection needed"


@app.route("/api/data")
def api_data():
    # Will be protected by Example 1
    return jsonify({"data": "This is protected API data"})


@app.route("/admin/dashboard")
def admin():
    # Will be blocked by Example 2
    return "Admin dashboard"


@app.route("/sensitive/update", methods=["GET", "POST"])
def sensitive_update():
    # Only POST will be protected by Example 3
    if request.method == "POST":
        return "Sensitive POST operation completed"
    return "View only - not protected for GET requests"


@app.route("/sensitive/health")
def health_check():
    # Excluded by Example 3
    return "Health check OK"


@app.route("/data/premium", methods=["POST"])
def premium_data():
    # Protected by Example 4 when specific parameters match
    return jsonify({"status": "Premium data operation completed"})


if __name__ == "__main__":
    app.run(debug=True)
