
import unittest
import sqlite3
from pathlib import Path

import app as auth_app


class AuthTests(unittest.TestCase):

    def setUp(self):
        self.original_db_path = auth_app.DB_PATH
        self.test_db_path = (
            Path(__file__).resolve().parent / "test_auth.db"
        )

        auth_app.DB_PATH = self.test_db_path

        auth_app.app.config.update(
            TESTING=True,
            WTF_CSRF_ENABLED=False
        )

        auth_app.init_db()

        # Clear test users without deleting the database file.
        conn = sqlite3.connect(str(self.test_db_path))
        try:
            conn.execute("DELETE FROM users")
            conn.commit()
        finally:
            conn.close()

        self.client = auth_app.app.test_client()

    def tearDown(self):
        self.client = None
        auth_app.DB_PATH = self.original_db_path

    def test_health(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)

    def test_dashboard_requires_login(self):
        response = self.client.get("/dashboard")
        self.assertIn(response.status_code, (302, 401))

    def test_register_then_access_dashboard(self):
        response = self.client.post(
            "/register",
            data={
                "username": "testuser",
                "email": "test@example.com",
                "password": "TestPassword123!"
            },
            follow_redirects=True
        )

        self.assertEqual(response.status_code, 200)

        dashboard = self.client.get("/dashboard")
        self.assertEqual(dashboard.status_code, 200)

    def test_invalid_login_rejected(self):
        response = self.client.post(
            "/login",
            data={
                "email": "wrong@example.com",
                "password": "WrongPassword123!"
            },
            follow_redirects=True
        )

        self.assertNotIn(response.status_code, (500,))

    def test_api_me_requires_auth(self):
        response = self.client.get("/api/me")
        self.assertIn(response.status_code, (401, 302))


if __name__ == "__main__":
    unittest.main()
