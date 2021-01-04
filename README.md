# CVEDataFeed

CVEDataFeed is a Python tool for converting and updating CVE data from [NVD](https://nvd.nist.gov/) to mongodb. This is also a backend tool for the [CVEData](https://cvedata.com) site which is an alternative for the CVEDetails.com.

## Features
1. Converting data from [NVD](https://nvd.nist.gov/) json file to mongodb, include CVEs information, vendors, products and versions affected.
2. Extending some properties for the CVEs: Vulnerabilities Type (get from descrtiption and CWE ID), Title (get from descrtiption and affected)
3. Keeping update newest data from [NVD](https://nvd.nist.gov/)
4. Statistics some information like total cve, total vendors, average base score,...
5. Organizing the data for easy showing on the website (see the [cvedata.com](https://cvedata.com)) 
6. Supporting the scheduler task both on [Heroku](https://devcenter.heroku.com/articles/scheduler) and [Google Cloud Function](https://cloud.google.com/scheduler/docs/tut-pub-sub)

## Installation

1. Clone this repo
```bash
git clone https://github.com/cuongmx/CVEDataFeed.git
```

2. Install requirements
```bash
pip3 install -r requirements.txt
```

3. Set environment variables
* (Require) **MONGODB_URI** for the mongo database information (example: mongodb://user:paSSw0rd@exampleserver.com/cvedata?retryWrites=true)
* (Option) **LOG_LEVEL** for the log output option, include ERROR, DEBUG or INFO. If not set, the default value is INFO.
* (Option) **LOG_FILE** for the log file option, include True or False. If set True, all output will write to the debug.log. If you not set, the default value is False.
```bash
export MONGODB_URI='mongodb://user:paSSw0rd@exampleserver.com/cvedata?retryWrites=true'
export LOG_LEVEL='INFO'
export LOG_FILE=True
```

## Usage

```bash
Usage cvedatafeed.py <action> [option]
List actions:
+ importonline: Import CVE from NVD
+ importoffline: Import CVE from a flolder
+ update: Update CVE From NVD
+ updatestat: Update Statistics
```

**Import online from NVD for the first time**
```
python3 cvedatafeed.py importonline
```

**If you have already downloaded CVE Json file to a folder, you should choose importoffline action**
```
python3 cvedatafeed.py importoffline
```

**For keep update newest CVE Data from NVD, please run update every 2h**
```
python3 cvedatafeed.py update
```

**CVEData.com show some statistic of this database, it's stored on statistics collection**
```
python3 cvedatafeed.py updatestat
```

*For keeping update and updatestat, you can use [Heroku](https://devcenter.heroku.com/articles/scheduler) or [Google Cloud Function](https://cloud.google.com/scheduler/docs/tut-pub-sub) with already supported file (included herokuscheduler.py and main.py)*

## Contributing
For this project to run in the long term, please join us, any pull requests are welcome. For big changes, first open an issue to discuss what you want to change. 

Contact me: cuongmx [at] gmail [dot] com

## License
Copyright (c) 2021, [cuongmx](https://cuong.mx). MIT License.
