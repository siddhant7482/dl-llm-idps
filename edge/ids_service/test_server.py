import os
import json
import unittest
import importlib

class TestServer(unittest.TestCase):
    def setUp(self):
        os.environ.pop("FORCE_CLASS", None)
        os.environ.pop("FORCE_CONF", None)
        os.environ.pop("MODEL_PATH", None)
        os.environ.pop("SCALER_PATH", None)
        os.environ.pop("LABEL_PATH", None)

    def test_predict_forced_class(self):
        os.environ["FORCE_CLASS"] = "DDOS attack-HOIC"
        os.environ["FORCE_CONF"] = "0.99"
        import server
        importlib.reload(server)
        client = server.app.test_client()
        resp = client.post("/predict", data=json.dumps({"features":[0]*52}), content_type="application/json")
        data = json.loads(resp.data.decode())
        self.assertEqual(data["class"], "DDOS attack-HOIC")
        self.assertGreaterEqual(data["confidence"], 0.99)

    def test_predict_benign_no_model(self):
        os.environ.pop("FORCE_CLASS", None)
        import server
        importlib.reload(server)
        client = server.app.test_client()
        resp = client.post("/predict", data=json.dumps({"features":[0]*52}), content_type="application/json")
        data = json.loads(resp.data.decode())
        self.assertEqual(data["class"], "Benign")
        self.assertGreaterEqual(data["confidence"], 1.0)

    def test_scaler_exception_handled(self):
        os.environ.pop("FORCE_CLASS", None)
        import server
        importlib.reload(server)
        class BadScaler:
            def transform(self, x):
                raise RuntimeError("bad")
        server.scaler = BadScaler()
        client = server.app.test_client()
        resp = client.post("/predict", data=json.dumps({"features":[0]*52}), content_type="application/json")
        data = json.loads(resp.data.decode())
        self.assertIn("class", data)
        self.assertIn("confidence", data)

if __name__ == "__main__":
    unittest.main()
