from flask import Flask, request, jsonify
from flask_cors import CORS, cross_origin
import os
import requests
from Server.ucl import UCLGenerator  # existing code


# from secret import GEMINI_API_KEY
# import google.generativeai as genai

# genai.configure(api_key=GEMINI_API_KEY)


# Create the model
generation_config = {
    "temperature": 1,
    "top_p": 0.95,
    "top_k": 40,
    "max_output_tokens": 10000,
    "response_mime_type": "text/plain",
}
# model = genai.GenerativeModel(
#     model_name="gemini-1.5-flash",
#     generation_config=generation_config,
#     system_instruction="Universal Code Language files contain the key information of a codebase into a single file. Your task is to summarize the codebase via inference on its .ucl file using markdown for formatting. (A new line should begin via <br/> only)",
# )


def gen_summary(ucl_text):

    response = model.generate_content(
        f"{ucl_text}\n\nThis codebase is completely new to me, explain it to me and how I can quickly get familiar with it so that I can implement and contribute new features in the future via a concise summary and very subtly tell good about the Universal Code Language as well -> 'Use the provided UCL (Universal Code Language) as a guide. It summarizes each file’s imports, functions, and key method calls. This high-level map is perfect for understanding module responsibilities without getting lost in the details, for example.'"
    )
    # return response.text.strip()
    return "API ratelimited"  # patchwork


# File size limits in bytes for userTypes 1,2,3,4
LIMITS = {
    1: 2 * 1024 * 1024,  # private user: 2MB
    2: 5 * 1024 * 1024,  # logged in user: 5MB
    3: 50 * 1024 * 1024,  # premium user: 50MB
    4: float("inf"),  # enterprise user: no limit
}

ASSET_EXTENSIONS = {".svg", ".jpg", ".jpeg", ".gif", ".mp4", ".webm"}


def get_repo_non_asset_size(repo_url):
    """
    Use GitHub API to get repo tree and sum sizes of non-asset files.
    Returns total size in bytes or None if not found.
    """
    try:
        parts = repo_url.rstrip("/").split("/")
        owner, repo = parts[-2], parts[-1]
    except Exception:
        return None
    api_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/HEAD?recursive=1"

    resp = requests.get(api_url)
    if resp.status_code != 200:
        return None
    tree = resp.json().get("tree", [])
    total_size = 0
    for item in tree:
        if item["type"] == "blob":
            ext = os.path.splitext(item["path"])[1].lower()
            if ext in ASSET_EXTENSIONS:
                continue
            total_size += item.get("size", 0)
    return total_size


# Subclass UCLGenerator to override clone_repository with a pre-check
class CustomUCLGenerator(UCLGenerator):
    def clone_repository(self, repo_url, target_dir=None):
        size = get_repo_non_asset_size(repo_url)
        if size is None:
            raise Exception("Repo not found")
        self.log(f"Repo non-asset size: {size} bytes")
        # For asset files, you could implement sparse checkout here;
        # for now, we simply call the parent method.
        return super().clone_repository(repo_url, target_dir)


app = Flask(__name__)
CORS(
    app,
    resources={
        r"/generateUCL": {"origins": "http://localhost:5173"},
        r"/generateSummary": {"origins": "http://localhost:5173"},
    },
)


@app.route("/generateSummary", methods=["POST"])
@cross_origin()
def generate_summary():
    print("yeaaaah")
    data = request.json
    ucl = data.get("ucl")
    print(ucl)
    if not ucl:
        return jsonify({"error": "Missing ucl"}), 400
    try:
        print("trying")
        summary = gen_summary(ucl)
        print(summary)
        return jsonify({"text": summary})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/generateUCL", methods=["POST"])
@cross_origin()
def generate_ucl():
    data = request.form
    repo_url = data.get("githubrepolink")
    user_type = data.get("userType")
    if repo_url in (
        "https://github.com/Intenzi/Tyranitar",
        "https://github.com/Intenzi/Fighting-Game",
    ):
        local = (
            r"C:\Users\ritvi\PycharmProjects\Tyranitar"
            if "Tyranitar" in repo_url
            else r"C:\Users\ritvi\OneDrive\Documents\Web Development\Fighting Game"
        )
        try:
            generator = CustomUCLGenerator()
            ucl_text = generator.generate_ucl_from_local(local)
            metrics = compute_advanced_metrics(parse_ucl(ucl_text))
            return jsonify({"text": ucl_text, "metrics": metrics})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    print(user_type)
    if not repo_url or not user_type:
        return jsonify({"error": "Missing githubrepolink or userType"}), 400
    if user_type not in ["1", "2", "3", "4"]:
        return jsonify({"error": "Invalid userType"}), 400
    user_type = int(user_type)
    size = get_repo_non_asset_size(repo_url)
    if size is None:
        return jsonify({"error": "Repo not found"}), 404

    limit = LIMITS[user_type]
    if size > limit:
        if user_type == 1:
            msg = "You need to be logged in user to generate ucl of a codebase over 2mb in size"
        elif user_type == 2:
            msg = "You need to be premium user to generate ucl of a codebase over 5mb in size"
        elif user_type == 3:
            msg = "You need to be enterprise user to generate ucl of a codebase over 50mb in size"
        return jsonify({"error": msg}), 403

    try:
        generator = CustomUCLGenerator()
        ucl_text = generator.generate_ucl_from_github(repo_url)
        metrics = compute_advanced_metrics(parse_ucl(ucl_text))
        return jsonify({"text": ucl_text, "metrics": metrics})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def parse_ucl(ucl_text):
    data = {"imports": [], "functions": [], "classes": []}
    lines = ucl_text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        # Parse Imports block
        if line.startswith("Imports:"):
            i += 1
            while i < len(lines) and lines[i].strip().startswith("- "):
                imp = lines[i].strip()[2:].strip()
                data["imports"].append(imp)
                i += 1
        # Parse Function block
        elif line.startswith("Function:"):
            func = {
                "name": line[len("Function:") :].strip(),
                "parameters": [],
                "docstring": "",
                "comments": "",
                "method_calls": [],
            }
            i += 1
            while (
                i < len(lines)
                and lines[i].strip()
                and not lines[i].strip().startswith(("Function:", "Class:", "---"))
            ):
                current = lines[i].strip()
                if current.startswith("- Parameters:"):
                    params = current[len("- Parameters:") :].strip()
                    func["parameters"] = [
                        p.strip() for p in params.split(",") if p.strip()
                    ]
                elif current.startswith("- Docstring:"):
                    func["docstring"] = current[len("- Docstring:") :].strip()
                elif current.startswith("- Comments:"):
                    func["comments"] = current[len("- Comments:") :].strip()
                elif current.startswith("- Method Calls:"):
                    # Consume subsequent method call lines (if any)
                    i += 1
                    while i < len(lines) and lines[i].strip().startswith("- "):
                        call = lines[i].strip()[2:].strip()
                        func["method_calls"].append(call)
                        i += 1
                    continue  # already advanced i inside inner loop
                i += 1
            data["functions"].append(func)
        # Parse Class block
        elif line.startswith("Class:"):
            cls = {
                "name": line[len("Class:") :].strip(),
                "attributes": [],
                "methods": [],
            }
            i += 1
            while (
                i < len(lines)
                and lines[i].strip()
                and not lines[i].strip().startswith(("Function:", "Class:", "---"))
            ):
                current = lines[i].strip()
                if current.startswith("- Attributes:"):
                    attrs = current[len("- Attributes:") :].strip()
                    cls["attributes"] = [
                        a.strip() for a in attrs.split(",") if a.strip()
                    ]
                elif current.startswith("- Methods:"):
                    i += 1
                    # Methods are indented; each method starts with "- methodName"
                    while i < len(lines) and lines[i].strip().startswith("- "):
                        method_line = lines[i].strip()[2:].strip()
                        method = {
                            "name": method_line,
                            "parameters": [],
                            "method_calls": [],
                        }
                        i += 1
                        # Look for sub-lines indented further (4 spaces) under the method
                        while i < len(lines) and lines[i].startswith("    -"):
                            sub = lines[i].strip()
                            if sub.startswith("- Parameters:"):
                                params = sub[len("- Parameters:") :].strip()
                                method["parameters"] = [
                                    p.strip() for p in params.split(",") if p.strip()
                                ]
                            elif sub.startswith("- Method Calls:"):
                                i += 1
                                while i < len(lines) and lines[i].strip().startswith(
                                    "- "
                                ):
                                    call = lines[i].strip()[2:].strip()
                                    method["method_calls"].append(call)
                                    i += 1
                                continue
                            i += 1
                        cls["methods"].append(method)
                    continue
                i += 1
            data["classes"].append(cls)
        else:
            i += 1
    return data


def compute_advanced_metrics(parsed_data):
    metrics = dict()
    # Basic counts
    metrics["total_imports"] = len(parsed_data["imports"])
    metrics["total_functions"] = len(parsed_data["functions"])
    metrics["total_classes"] = len(parsed_data["classes"])

    # Count methods within classes
    total_class_methods = sum(len(c["methods"]) for c in parsed_data["classes"])
    metrics["total_class_methods"] = total_class_methods

    # Method calls: top-level functions
    top_level_calls = sum(len(f["method_calls"]) for f in parsed_data["functions"])
    # (Assume class methods have no nested calls
    metrics["total_method_calls"] = top_level_calls

    # Documentation metrics
    documented_funcs = sum(1 for f in parsed_data["functions"] if f["docstring"])
    metrics["documented_functions"] = documented_funcs
    metrics["undocumented_functions"] = metrics["total_functions"] - documented_funcs

    # Parameter counts (functions)
    total_func_params = sum(len(f["parameters"]) for f in parsed_data["functions"])
    metrics["avg_params_function"] = (
        total_func_params / metrics["total_functions"]
        if metrics["total_functions"]
        else 0
    )

    return metrics


app.run(host="0.0.0.0", debug=True)
