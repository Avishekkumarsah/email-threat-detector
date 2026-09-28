import requests
import re

BASE_URL = "http://127.0.0.1:5000"

def test_live_app():
    s = requests.Session()

    print("1. Fetching registration page...")
    r = s.get(f"{BASE_URL}/register")
    assert r.status_code == 200, f"Register GET failed: {r.status_code}"
    csrf_match = re.search(r'name="csrf_token"\s+value="([^"]+)"', r.text)
    csrf_token = csrf_match.group(1) if csrf_match else ""

    print("2. Registering new user 'live_user_99' ('Live_User_99@example.com')...")
    reg_data = {
        "csrf_token": csrf_token,
        "username": "live_user_99",
        "email": "Live_User_99@example.com",
        "password": "TestPassword123!",
        "confirm_password": "TestPassword123!"
    }
    r = s.post(f"{BASE_URL}/register", data=reg_data, allow_redirects=True)
    assert r.status_code == 200, f"Registration POST failed: {r.status_code}"
    assert "Dashboard" in r.text or "scans" in r.text.lower(), "Registration did not redirect to dashboard"
    print("✓ Registration successful!")

    print("3. Logging out...")
    r = s.get(f"{BASE_URL}/logout", allow_redirects=True)
    assert r.status_code == 200

    print("4. Testing case-insensitive email login with UPPERCASE email 'LIVE_USER_99@EXAMPLE.COM'...")
    r = s.get(f"{BASE_URL}/login")
    csrf_match = re.search(r'name="csrf_token"\s+value="([^"]+)"', r.text)
    csrf_token = csrf_match.group(1) if csrf_match else ""

    login_data = {
        "csrf_token": csrf_token,
        "username_or_email": "LIVE_USER_99@EXAMPLE.COM",
        "password": "TestPassword123!"
    }
    r = s.post(f"{BASE_URL}/login", data=login_data, allow_redirects=True)
    assert r.status_code == 200, f"Login POST failed: {r.status_code}"
    assert "Invalid" not in r.text, "Login failed with Invalid email/password message"
    assert "live_user_99" in r.text or "Dashboard" in r.text, "Login did not log user in"
    print("✓ Uppercase email login persistence test PASSED!")

    print("5. Logging out and logging in as Admin...")
    s.get(f"{BASE_URL}/logout")
    r = s.get(f"{BASE_URL}/login")
    csrf_match = re.search(r'name="csrf_token"\s+value="([^"]+)"', r.text)
    csrf_token = csrf_match.group(1) if csrf_match else ""

    admin_login = {
        "csrf_token": csrf_token,
        "username_or_email": "admin@threatdetector.local",
        "password": "Admin@123456"
    }
    r = s.post(f"{BASE_URL}/login", data=admin_login, allow_redirects=True)
    assert r.status_code == 200

    print("6. Checking Admin User Directory at /admin...")
    r = s.get(f"{BASE_URL}/admin")
    assert r.status_code == 200
    assert "Last Active" in r.text, "'Last Active' column missing from Admin table"
    assert "live_user_99" in r.text, "Registered user missing from Admin user table"
    print("✓ Admin User Directory test PASSED! (Displays all users and Last Active column)")

    print("7. Testing Live Monitoring page and 'Poll Now' feature...")
    r = s.get(f"{BASE_URL}/monitor")
    assert r.status_code == 200
    assert "Poll Now" in r.text or "poll-now" in r.text, "'Poll Now' feature missing from Monitor page"

    csrf_match = re.search(r'name="csrf_token"\s+value="([^"]+)"', r.text)
    csrf_token = csrf_match.group(1) if csrf_match else ""

    r = s.post(f"{BASE_URL}/monitor/poll-now", data={"csrf_token": csrf_token}, allow_redirects=True)
    assert r.status_code == 200
    print("✓ Live Inbox Monitoring test PASSED!")

    print("\n=========================================")
    print("ALL END-TO-END LIVE APP TESTS PASSED SUCCESSFULLY!")
    print("=========================================")

if __name__ == "__main__":
    test_live_app()
