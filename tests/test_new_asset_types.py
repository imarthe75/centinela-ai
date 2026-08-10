"""
Unit test for 5 New Asset Types scanning logic in auditor_ext (with subprocess mocks).
"""
import unittest
from unittest.mock import patch, MagicMock
from auditors.auditor_ext import handle_asset_discovered

class TestNewAssetTypesRouting(unittest.TestCase):
    @patch("subprocess.run")
    def test_handle_ai_llm_endpoint(self, mock_sub):
        data = {"id": 99991, "type": "AI-LLM-Endpoint", "endpoint": "http://127.0.0.1:8000/v1"}
        handle_asset_discovered(data)

    @patch("subprocess.run")
    def test_handle_api_gateway(self, mock_sub):
        data = {"id": 99992, "type": "API-Gateway", "endpoint": "http://127.0.0.1:8080"}
        handle_asset_discovered(data)

    @patch("subprocess.run")
    def test_handle_cloud_serverless(self, mock_sub):
        data = {"id": 99993, "type": "Cloud-Serverless", "endpoint": "arn:aws:lambda:us-east-1:123456789:function:test"}
        handle_asset_discovered(data)

    @patch("subprocess.run")
    def test_handle_identity_idp(self, mock_sub):
        data = {"id": 99994, "type": "Identity-IdP", "endpoint": "http://127.0.0.1:9000"}
        handle_asset_discovered(data)

    @patch("subprocess.run")
    def test_handle_cicd_pipeline(self, mock_sub):
        data = {"id": 99995, "type": "CICD-Pipeline", "endpoint": "http://10.4.3.10/devops/runner"}
        handle_asset_discovered(data)

if __name__ == "__main__":
    unittest.main()
