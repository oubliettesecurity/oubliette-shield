"""Tests for OpenAPI/Swagger documentation."""

import json
import pytest


class TestOpenAPISpec:
    """Tests for static OpenAPI spec."""

    def test_spec_is_valid_dict(self):
        from oubliette_shield.openapi import OPENAPI_SPEC
        assert isinstance(OPENAPI_SPEC, dict)
        assert "openapi" in OPENAPI_SPEC
        assert OPENAPI_SPEC["openapi"].startswith("3.0")

    def test_spec_has_info(self):
        from oubliette_shield.openapi import OPENAPI_SPEC
        assert "info" in OPENAPI_SPEC
        assert "title" in OPENAPI_SPEC["info"]
        assert "version" in OPENAPI_SPEC["info"]

    def test_spec_has_all_endpoints(self):
        from oubliette_shield.openapi import OPENAPI_SPEC
        paths = OPENAPI_SPEC.get("paths", {})
        assert "/analyze" in paths
        assert "/health" in paths
        assert "/sessions" in paths
        assert "/dashboard" in paths

    def test_analyze_endpoint_has_post(self):
        from oubliette_shield.openapi import OPENAPI_SPEC
        assert "post" in OPENAPI_SPEC["paths"]["/analyze"]

    def test_schemas_defined(self):
        from oubliette_shield.openapi import OPENAPI_SPEC
        schemas = OPENAPI_SPEC.get("components", {}).get("schemas", {})
        assert "AnalyzeRequest" in schemas
        assert "AnalyzeResponse" in schemas
        assert "HealthResponse" in schemas
        assert "Error" in schemas

    def test_security_scheme(self):
        from oubliette_shield.openapi import OPENAPI_SPEC
        schemes = OPENAPI_SPEC.get("components", {}).get("securitySchemes", {})
        assert "ApiKeyAuth" in schemes
        assert schemes["ApiKeyAuth"]["type"] == "apiKey"

    def test_swagger_ui_html(self):
        from oubliette_shield.openapi import SWAGGER_UI_HTML
        assert "swagger-ui" in SWAGGER_UI_HTML
        assert "SwaggerUIBundle" in SWAGGER_UI_HTML
        assert "openapi.json" in SWAGGER_UI_HTML

    def test_spec_serializable(self):
        from oubliette_shield.openapi import OPENAPI_SPEC
        # Should be JSON-serializable
        json_str = json.dumps(OPENAPI_SPEC)
        assert len(json_str) > 0
        parsed = json.loads(json_str)
        assert parsed["openapi"] == OPENAPI_SPEC["openapi"]


class TestOpenAPIBlueprint:
    """Tests for OpenAPI endpoints in Flask blueprint."""

    @pytest.fixture
    def client(self):
        try:
            from flask import Flask
        except ImportError:
            pytest.skip("Flask not installed")
        from oubliette_shield import Shield, create_shield_blueprint
        app = Flask(__name__)
        # Use a shield with no LLM to avoid external calls
        shield = Shield(ml_client=None, llm_judge=None)
        bp = create_shield_blueprint(shield)
        app.register_blueprint(bp, url_prefix="/shield")
        app.config["TESTING"] = True
        return app.test_client()

    def test_openapi_json_endpoint(self, client):
        resp = client.get("/shield/openapi.json")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "openapi" in data

    def test_swagger_ui_endpoint(self, client):
        resp = client.get("/shield/docs")
        assert resp.status_code == 200
        assert b"swagger-ui" in resp.data
