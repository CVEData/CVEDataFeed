from apscheduler.schedulers.blocking import BlockingScheduler
import cvedatafeed

sched = BlockingScheduler()

@sched.scheduled_job('interval', hours=2)
def updatecve():
	cvedatafeed.updateCVEOnline()

@sched.scheduled_job('cron', hour=0, minute=30)
def updatestatistic():
	cvedatafeed.updateCVEOnline()

sched.start()