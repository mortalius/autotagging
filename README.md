# Tag replicator

Scans for snapshots that do not have required tags, tries to gather tags from volume/instance and/or AMI, and then assigns tags to:
* snapshots with tags from volume/instance/ami
* volumes with tags from instance/ami

### Usage
```
usage: tagreplicator.py [-h] [--profile PROFILE] [--region REGION] --tags TAGS
                        [--ami-lookup] [--stats-only] [--report] [--dry-run]

Tag replicator. Scans for <tags> untagged snapshots and tags snapshot
with volume/instance/ami tag.

optional arguments:
  -h, --help         show this help message and exit
  --profile PROFILE  awscli profile to use
  --region REGION    AWS region (us-east-1 by default)
  --tags TAGS        List of tags to replicate, separated by comma, e.g
                     Owner,cost (case sensitive
  --ami-lookup       Lookup for tags from AMI. False by default
  --stats-only       Print stats on snapshots total vs <tags> untagged snapshots and exit
  --report           Generate csv report
  --dry-run          No actual tagging. Could be used with --report
```


### Examples

In this example script looks for all snapshots owned by your account in `us-east-1` region that do not have one or more of the tags `cost/Project/Technical owner`. Then searches for volumes/instances and AMI tags as ami-lookup option is used, and then tags snapshots and volumes with missing tags.
```
tagreplicator.py --profile myprofile --region us-east-1 --tags "cost,Project,Technical Owner" --ami-lookup
```

### Lambda usage

Script can be easily run as lambda job by specifying lambda handler as `lambda_handler`. 

When running as lambda job, script looks for next environment variables:

| Variable  | Description  |
|---        |---           |
| REGION    | Region       |
| TAGS      | List of tags |
| AMI_LOOKUP| Look for AMI tags. Set to `True` |
| DRYRUN    | Dry run      |
