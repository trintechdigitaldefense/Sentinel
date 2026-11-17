# © 2026 TrinTech Digital Defense — isolated dashboard browser security tests
from __future__ import annotations

import threading
from http.server import ThreadingHTTPServer

import pytest


@pytest.fixture
def dashboard_server(monkeypatch):
    pytest.importorskip("playwright.sync_api")
    import modules.dashboard_impl as dashboard

    dashboard._Handler.token = "browser-test-token"
    dashboard._Handler.allow_control = True
    monkeypatch.setattr(
        dashboard,
        "collect_full",
        lambda: {
            "host": "browser-test-host",
            "local_ip": "127.0.0.1",
            "version": "test",
            "ts": "2026-11-17T00:00:00",
            "critical": {
                "open": [{"id": "x');window.__sentinelXss=3;//", "type": "test", "count": 1}],
                "open_count": 1,
            },
            "realtime": {"level": "CLEAR", "threats": []},
        },
    )
    monkeypatch.setattr(
        dashboard,
        "_generate_dashboard_pdfs",
        lambda action: {
            "ok": True,
            "download": "/api/report/download?name=client-report.pdf",
            "downloads": [
                "/api/report/download?name=client-report.pdf",
                "javascript:window.__sentinelXss=1",
                "//attacker.invalid/api/report/download?name=evil.pdf",
                "/api/report/download?name=%3Csvg%3E.pdf",
            ],
        },
    )

    server = ThreadingHTTPServer(("127.0.0.1", 0), dashboard._Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_browser_login_xss_report_links_and_security_headers(dashboard_server):
    pytest.importorskip("playwright.sync_api")
    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()
        page_errors = []
        page.on("pageerror", lambda error: page_errors.append(str(error)))

        response = page.goto(dashboard_server)
        assert response is not None and response.status == 200
        assert page.locator("#token").is_visible()
        assert page.locator("#realtime").count() == 0

        page.locator("#token").fill("browser-test-token")
        page.locator("button[type=submit]").click()
        page.locator("#realtime table").wait_for()
        assert page.url == dashboard_server
        assert "browser-test-token" not in page.content()
        assert page.evaluate("typeof renderThreats") == "function", page_errors

        # Alert IDs are data attributes, never interpolated into inline JavaScript.
        page.evaluate("window.__sentinelXss = 0")
        ack_button = page.locator("button[data-alert-id]")
        assert ack_button.count() == 1
        assert ack_button.get_attribute("onclick") is None
        page.on("dialog", lambda dialog: dialog.dismiss())
        ack_button.click()
        assert page.evaluate("window.__sentinelXss") == 0

        cookies = context.cookies()
        session = next(cookie for cookie in cookies if cookie["name"] == "sentinel_token")
        assert session["httpOnly"] is True
        assert session["sameSite"] == "Strict"

        # Query-string credentials must not bypass the login screen.
        unauth_context = browser.new_context()
        unauth_page = unauth_context.new_page()
        unauth_page.goto(dashboard_server + "?token=browser-test-token")
        assert unauth_page.locator("#token").is_visible()
        assert unauth_page.locator("#realtime").count() == 0

        # Threat telemetry is rendered as text, never parsed as markup.
        page.evaluate(
            """() => {
              window.__sentinelXss = 0;
              renderThreats({
                level: "HIGH",
                threats: [{
                  severity: "HIGH",
                  type: '<img src=x onerror="window.__sentinelXss=1">',
                  detail: '<svg onload="window.__sentinelXss=2">'
                }]
              });
            }"""
        )
        assert page.locator("#realtime img, #realtime svg").count() == 0
        assert page.locator("#realtime table").inner_text().find("<img") >= 0
        assert page.evaluate("window.__sentinelXss") == 0

        # A compromised report API cannot inject script URLs or cross-origin links.
        page.evaluate("runAction('pdf-report')")
        page.locator("#report-links a").first.wait_for()
        hrefs = page.locator("#report-links a").evaluate_all(
            "(nodes) => nodes.map((node) => node.getAttribute('href'))"
        )
        assert hrefs
        assert all(href == "/api/report/download?name=client-report.pdf" for href in hrefs)
        assert page.locator("#pdf-viewer-wrap iframe").count() == 1
        assert page.evaluate("window.__sentinelXss") == 0

        secured_response = page.reload()
        assert secured_response is not None
        headers = {key.lower(): value for key, value in secured_response.headers.items()}
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["referrer-policy"] == "no-referrer"
        assert headers["x-frame-options"] == "SAMEORIGIN"
        assert "frame-ancestors 'self'" in headers["content-security-policy"]

        unauth_context.close()
        context.close()
        browser.close()
