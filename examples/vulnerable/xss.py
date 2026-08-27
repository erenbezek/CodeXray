def render(request):
    value = request.args["q"]
    body = f"<p>{value}</p>"
    response = Response(body)
    return response
