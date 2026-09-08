import os

from flask import request


UPLOAD_DIR = "/uploads"
open(os.path.join(UPLOAD_DIR, secure_filename(request.args["f"])))
