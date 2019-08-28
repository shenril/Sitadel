from lib.utils.container import Services

output = Services.get("output")
request = Services.get("request_factory")

if request.redirect == True:
    output.info("For better waf detection we recommend you to run with --no-redirect")
