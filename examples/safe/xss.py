import html


def render(request):
    value = request.args["q"]
    body = f"<p>{html.escape(value)}</p>"
    response = Response(body)
    return response
