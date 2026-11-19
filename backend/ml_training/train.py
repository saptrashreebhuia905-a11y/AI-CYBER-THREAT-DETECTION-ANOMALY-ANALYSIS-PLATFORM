import json

from app.detection.ml_model import get_model_profile


if __name__ == "__main__":
    print(json.dumps(get_model_profile(), indent=2))
