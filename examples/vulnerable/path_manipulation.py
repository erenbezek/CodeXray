from flask import request


path = request.args["f"]
open(path)
