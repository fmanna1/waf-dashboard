from waf_app import extract_features
import joblib

clf = joblib.load("ml_model.joblib")

def test_extract_features():
    assert isinstance(extract_features("1=1"), list)

def test_model_prediction():
    assert clf.predict([extract_features("<script>")])[0] == 1
