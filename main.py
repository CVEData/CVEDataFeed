import cvedatafeed
import base64

"""Function for Triggered from a message on a Cloud Pub/Sub topic.
Args:
     event (dict): Event payload.
     context (google.cloud.functions.Context): Metadata for the event.
"""
def googlecloud_trigger(event, context):
	try:
		param = base64.b64decode(event['data']).decode('utf-8')
		if param == "update":
			cvedatafeed.updateCVEOnline()
		elif param == "updatestat":
			cvedatafeed.updateStatistics()
		else:
			cvedatafeed.printUsage()
			exit(0)
	except Exception:
		cvedatafeed.printUsage()
		exit(0)