# Replicates tags to snapshot and volume using tags from volume/instance and ami(from snapshot description)
# Dmitry Aliev (c)

# TODO
# README.md
# Add info on where tag came from
# use more convinient arg parser


from __future__ import print_function
import boto3
from botocore.exceptions import ClientError
from collections import Counter
import re
import os
import csv
import sys
import argparse
import pprint
from datetime import datetime


def parse_arguments():
    REGION = 'us-east-1'
    PROFILE = None
    parser = argparse.ArgumentParser(description="""
Tag replicator. Scans for untagged resources (AMIs or Snapshots) and tags them with tags from associated resources.
""")
    subparsers = parser.add_subparsers(help='Tagging Mode')

    parser.add_argument("--profile", required=False, default=PROFILE, type=str,
                        help="awscli profile to use")
    parser.add_argument("--region", required=False, default=REGION, type=str,
                        help="AWS region (us-east-1 by default)")

    # Snapshots tagging mode
    snapshot_parser = subparsers.add_parser('snapshot_mode', help='Find untagged Snapshots and propogate tags to them from associated volumes and instances')
    snapshot_parser.set_defaults(mode='snapshot_mode')
    snapshot_parser.add_argument("--tags", action='store', type=str, required=True,
                                 help="List of tags to replicate, separated by comma, e.g Owner,cost (case sensitive)")
    snapshot_parser.add_argument("--tag-untagged-with", action='store', type=str, required=False, metavar='TAG:VALUE',
                                 help="Tag snapshots and volumes with <tag:value> where <tag> hadn't been found.")
    snapshot_parser.add_argument("--ami-lookup", action="store_true", default=False,
                                 help="Lookup for tags from AMI. False by default")
    snapshot_parser.add_argument("--stats-only", action="store_true", default=False,
                                 help="Print stats on snapshots total vs <tags> untagged snapshots and exit")
    snapshot_parser.add_argument("--report", action="store_true", default=False,
                                 help="Generate csv report")
    snapshot_parser.add_argument("--dry-run", action="store_true", default=False,
                                 help="No actual tagging. Could be used with --report")

    # AMI tagging mode
    ami_parser = subparsers.add_parser('ami_mode', help='Find untagged AMIs and propagate tags to them from associated snapshots')
    ami_parser.set_defaults(mode='ami_mode')
    ami_parser.add_argument("--tags", action='store', type=str, required=True,
                            help="List of tags to replicate, separated by comma, e.g Owner,cost (case sensitive)")
    ami_parser.add_argument("--tag-untagged-with", action='store', type=str, required=False, metavar='TAG:VALUE',
                            help="Tag AMIs with <tag:value> where <tag> hadn't been found.")
    ami_parser.add_argument("--stats-only", action="store_true", default=False,
                            help="Print stats on AMIs total vs <tags> untagged AMIs and exit")
    ami_parser.add_argument("--report", action="store_true", default=False,
                            help="Generate csv report")
    ami_parser.add_argument("--dry-run", action="store_true", default=False,
                            help="No actual tagging. Could be used with --report")

    args = parser.parse_args()

    profile = args.profile
    region = args.region
    tag_mode = args.mode

    tags_list = args.tags.split(',')
    tag_untagged = args.tag_untagged_with
    stats_only = args.stats_only
    dryrun = args.dry_run
    report = args.report

    generic_params = (profile, region)
    if tag_mode == "ami_mode":
        mode_params = (tags_list, tag_untagged, stats_only, dryrun, report)
    elif tag_mode == "snapshot_mode":
        ami_lookup = args.ami_lookup
        mode_params = (tags_list, tag_untagged, ami_lookup, stats_only, dryrun, report)

    return (tag_mode, generic_params, mode_params)


class TagReplicator:

    def __init__(self):
        self.ec2 = None
        self.ec2client = None

        self.profile = None
        self.region = 'us-east-1'
        # self.stats_only = False
        # self.dryrun = False
        # self.report = False

        self.owner_account_id = ''
        self.count_tagged_resources = Counter()
        self.count_propagated_tags = Counter()

        self.start_time = None

    def get_untagged_snapshots(self, account_id, tags):
        self.print("Getting untagged snapshots..")
        all_owned_snapshots_filter = [
            {
                'Name': 'owner-id',
                'Values': [account_id]
            }
        ]
        snaps_all = self.ec2.snapshots.filter(Filters=all_owned_snapshots_filter)
        snaps_all_ids = [s.snapshot_id for s in snaps_all]

        tags_filter = [
            {
                'Name': 'owner-id',
                'Values': [account_id]
            }
        ]
        for tag in tags:
            tags_filter.append(
                {
                    'Name': 'tag-key',
                    'Values': [tag]
                }
            )
        snaps_tagged = self.ec2.snapshots.filter(Filters=tags_filter)
        snaps_tagged_ids = [s.snapshot_id for s in snaps_tagged]
        return set(snaps_all_ids) - set(snaps_tagged_ids)

    def get_untagged_amis(self, account_id, tags):
        self.print("Getting untagged AMIs..")
        all_owned_amis_filter = [
            {
                'Name': 'owner-id',
                'Values': [account_id]
            }
        ]
        tags_filter = [
            {
                'Name': 'owner-id',
                'Values': [account_id]
            }
        ]
        for tag in tags:
            tags_filter.append(
                {
                    'Name': 'tag-key',
                    'Values': [tag]
                }
            )
        amis_all = self.ec2client.describe_images(Filters=all_owned_amis_filter)['Images']
        amis_all_ids = [s['ImageId'] for s in amis_all]
        amis_tagged = self.ec2client.describe_images(Filters=tags_filter)['Images']
        amis_tagged_ids = [s['ImageId'] for s in amis_tagged]
        return set(amis_all_ids) - set(amis_tagged_ids)


    def volume_exists(self, id):
        try:
            self.ec2.Volume(id).size
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidVolume.NotFound':
                return False
            else:
                raise e
        return True

    def tag_resource_with_tags(self, resource, tags, dryrun, index=0):
        prefix = resource.id.split('-')[0]
        self.count_propagated_tags[prefix] += len(tags)
        tags_to_create = []
        for key, value in tags.iteritems():
            tags_to_create.append(
                {
                    'Key': key,
                    'Value': value
                }
            )
            self.print("{idx} Tagging {dst:22} with tag:{key}={value} {note}".format(
                idx=index if index else '',
                dst=resource.id,
                key=key,
                value=value,
                note='(dry run)' if dryrun else ''))
        if dryrun:
            return
        resource.create_tags(Tags=tags_to_create)

    def extract_untagged(self, src_details, dst_details, tags):
        missing_tags = {}
        for dtag in tags:
            if src_details['tags'].get(dtag):
                if not dst_details['tags'].get(dtag):
                    missing_tags[dtag] = src_details['tags'].get(dtag)
        return missing_tags

    def get_ami_details(self, ami):
# {'ami_id': 'ami-04994d7e',
#  'snapshots': ['snap-0f029f88f550fdc1f'],
#  'tags': {'Business Owner': 'Elaine Wilson',
#           'Component': 'APP',
#           'Description': 'CUS-PROD-APP-backend',
#           'Environment': 'PROD',
#           'JiraTicket': 'NFR-661',
#           'Name': 'HMHVPC01-CUSPRODAPP02',
#           'Project': 'CUS',
#           'Technical Owner': 'John Hurley',
#           'Tier': 'APP',
#           'cost': 'common_userstore',
#           'cpm_policy_name': 'CNA_Dublin_Prod_Weekly',
#           'cpm_server_id': '3122ead2-8b45-41c9-95b3-14050dbb6350'}}
        try:
            _tags = ami.tags
            ami_tags = {s['Key']: s['Value'] for s in _tags} if _tags else {}
            ami_snapshots = [mapping.get('Ebs').get('SnapshotId') for mapping in ami.block_device_mappings if mapping.get('Ebs')]
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidAMIID.NotFound':
                return {}
        else:
            return {'image_id': ami.image_id,
                    'tags': ami_tags,
                    'snapshots': ami_snapshots
                   }


    def get_ami_details_by_id(self, ami_id):
        try:
            # response = self.ec2client.describe_images(ImageIds=[ami_id])
            response = self.ec2.Images(ami_id)
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidAMIID.NotFound':
                return {}

        _tags = response['Images'][0].get('Tags')
        ami_tags = {s['Key']: s['Value'] for s in _tags} if _tags else {}

        _BlockDeviceMappings = response['Images'][0].get('BlockDeviceMappings')
        snapshots = [mapping.get('Ebs').get('SnapshotId') for mapping in _BlockDeviceMappings]
        return {'ami_id': ami_id,
                'tags': ami_tags,
                'snapshots': snapshots
               }

    def get_snapshot_details(self, snap):
        # TODO: Check if snapshot exists ??
        snap_tags = {s['Key']: s['Value'] for s in snap.tags} if snap.tags else {}
        description = snap.description
        snap_details = {'id': snap.id,
                        'volume_id': snap.volume_id,
                        'description': description,
                        'volume_size': snap.volume_size,
                        'start_date': snap.start_time.strftime("%d/%m/%Y"),
                        'tags': snap_tags}

        d_ami = re.search(r'ami-[\w\d]+', description)
        snap_details['description_ami'] = d_ami.group(0) if d_ami else ''

        d_vol = re.search(r'ami-[\w\d]+', description)
        snap_details['description_vol'] = d_vol.group(0) if d_vol else ''

        d_inst = re.search(r'ami-[\w\d]+', description)
        snap_details['description_instance'] = d_inst.group(0) if d_vol else ''

        return snap_details

    def get_volume_details(self, vol):
        try:
            vol_tags = {s['Key']: s['Value'] for s in vol.tags} if vol.tags else {}
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidVolume.NotFound':
                return {}
        return {'id': vol.id,
                'tags': vol_tags}

    def get_instance_details(self, instance):
        # TODO: Check if instance exists
        instance_tags = {s['Key']: s['Value'] for s in instance.tags} if instance.tags else {}
        return {'id': instance.id,
                'state': instance.state['Name'],
                'tags': instance_tags}

    def print(self, msg):
        d = datetime.now() - self.start_time
        print("%3s %s %s" % (d.seconds, 'sec |', msg))

    def connect(self, profile, region):
        self.start_time = datetime.now()
        # TODO: Exception handling, Return tuple (true/false, error message)
        session = boto3.Session(profile_name=profile, region_name=region)
        self.ec2 = session.resource('ec2')
        self.ec2client = session.client('ec2')

        try:
            self.owner_account_id = session.client('sts').get_caller_identity()['Account']
        except ClientError as e:
            raise e
        return True

    def do_snapshot_tagging(self, desired_tags, dryrun, stats_only, ami_lookup, do_report, do_tag_untagged):
        untagged_snapshots = self.get_untagged_snapshots(self.owner_account_id, desired_tags)

        self.print("%-35s %s" % ("Account Id:", self.owner_account_id))
        self.print("%-35s %s" % ("Region:", self.region))
        self.print("%-35s %s" % ("Tags to replicate:", ', '.join(desired_tags)))
        self.print("%-35s %s" % ("Snapshots to process (untagged):", len(untagged_snapshots)))

        if stats_only:
            return True

        if do_report:
            csv_filename = "{0}_{1}_{2}".format(self.owner_account_id, self.region, "untagged_snapshots.csv")
            csv_file = open(csv_filename, 'w')
            csv_out = csv.writer(csv_file)

            header_row = ['SnapshotId']
            header_row += ['SnapTag: ' + tag for tag in desired_tags]
            header_row += ['SnapshotDescription', 'StartDate', 'VolumeId', 'VolumeSize']
            header_row += ['VolTag: ' + tag for tag in desired_tags]
            header_row += ['InstanceId', 'InstanceState']
            header_row += ['InstanceTag: ' + tag for tag in desired_tags]
            header_row += ['comment1', 'comment2', 'comment3']

            csv_out.writerow(header_row)

        for idx, snapshot_id in enumerate(untagged_snapshots):
            snap = self.ec2.Snapshot(snapshot_id)
            snap_details = self.get_snapshot_details(snap)
            volume = self.ec2.Volume(snap_details['volume_id'])
            volume_details = self.get_volume_details(volume)
            instance = None
            instance_details = {}

            extracted_tags = {}
            tags_for_volume = {}
            tags_for_snapshot = {}


            # print('{idx}'.format(idx=str(idx)), end="\r")
            comment1 = comment2 = comment3 = ''

            # Gather tags to replicate for each entity vol snap
            # Snap <- Vol
            # if instance attached:
            #         Vol <- Instance
            # Snap <-------- Instance
            # if ami_lookup and ami found in description
            # Snap <-------- AMI
            #         Vol <- AMI

            is_volume_exists = self.volume_exists(snap_details['volume_id'])
            if is_volume_exists:
                extracted_tags = self.extract_untagged(volume_details, snap_details, desired_tags)
                tags_for_snapshot = dict(extracted_tags.items() + tags_for_snapshot.items())

                # If volume have instance attached
                # if volume.attachments and set(volume_details['tags'].keys()) != set(desired_tags):
                if volume.attachments:
                    # And volume has some desired tags omitted So try to complete with instance tags.
                    if (set(desired_tags) - set(volume_details['tags'])):
                        instance = self.ec2.Instance(volume.attachments[0]['InstanceId'])
                        instance_details = self.get_instance_details(instance)
                        # complete tags_for_snapshot with instance tags
                        extracted_tags = self.extract_untagged(instance_details, snap_details, desired_tags)
                        tags_for_snapshot = dict(extracted_tags.items() + tags_for_snapshot.items())

                        # complete tags_for_volume with instance tags
                        extracted_tags = self.extract_untagged(instance_details, volume_details, desired_tags)
                        tags_for_volume = dict(extracted_tags.items() + tags_for_volume.items())
                    else:
                        comment3 = "No tagging needed for volume"
            else:
                comment1 = "Volume NOT exists"

            # AMI lookup if requested
            if ami_lookup and snap_details['description_ami']:
                ami_details = self.get_ami_details_by_id(snap_details['description_ami'])
                if ami_details:
                    # Snapshot <- AMI gathering
                    extracted_tags = self.extract_untagged(ami_details, snap_details, desired_tags)
                    # snap_tags_before_ami = tags_for_snapshot
                    # tags_from_ami_only = {k:extracted_tags[k] for k in set(extracted_tags) - set(tags_for_snapshot)}
                    tags_for_snapshot = dict(extracted_tags.items() + tags_for_snapshot.items())

                    # if ami_details['tags']:
                    #     print('AMI tags: ', ami_details['tags'])
                    #     print('Snap tags before: ', snap_tags_before_ami)
                    #     print('AMI tags not it Snap: ', tags_from_ami_only)

                    # Volume <- AMI gathering
                    if self.volume_exists(snap_details['volume_id']):
                        extracted_tags = self.extract_untagged(ami_details, volume_details, desired_tags)
                        tags_for_volume = dict(extracted_tags.items() + tags_for_volume.items())

            # Add default tag to snap/volume
            default_tag, default_value = do_tag_untagged.split(':')

            ### TODO REVIEW
            volume_needs_default_tagging = True if (not tags_for_volume and is_volume_exists and not volume_details.get('tags').get(default_tag)) else False

            # if requested AND no desired tag was found previously
            if do_tag_untagged and not tags_for_snapshot.get(default_tag):
                tags_for_snapshot[default_tag] = default_value
            # if requested AND no desired tag was found previously AND volume had no tag  !!!!!!! TODO Rework condition to Set
            # if do_tag_untagged and not tags_for_volume.get(default_tag) :
            if do_tag_untagged and volume_needs_default_tagging:
                tags_for_volume[default_tag] = default_value

            # Tagging with gathered tags
            if tags_for_snapshot:
                comment2 = "Tagged with: %s" % (', '.join([k + ":" + v for k, v in tags_for_snapshot.iteritems()]))
                self.count_tagged_resources['snap'] += 1
                self.tag_resource_with_tags(snap, tags_for_snapshot, dryrun, idx)
            else:
                comment2 = 'No any tags found for snapshot'

            if is_volume_exists:
                if tags_for_volume:
                    comment3 = "Tagged with: %s" % (', '.join([k + ":" + v for k, v in tags_for_volume.iteritems()]))
                    self.count_tagged_resources['vol'] += 1
                    self.tag_resource_with_tags(volume, tags_for_volume, dryrun, idx)
                else:
                    comment3 = 'No any tags found for volume' if not comment3 else comment3

            # Assemble row for csv
            if do_report:
                data_row = [snap_details['id']]
                data_row += [snap_details.get('tags', {}).get(tag, '') for tag in desired_tags]
                data_row += [snap_details['description'],
                             snap_details['start_date'],
                             volume_details.get('id'),
                             snap_details.get('volume_size')
                             ]
                data_row += [volume_details.get('tags', {}).get(tag, '') for tag in desired_tags]
                data_row += [instance_details.get('id'),
                             instance_details.get('state')
                             ]
                data_row += [instance_details.get('tags', {}).get(tag, '') for tag in desired_tags]
                data_row += [comment1, comment2, comment3]

                csv_out.writerow(data_row)

        if do_report:
            csv_file.close()

        note = "(forecast)" if dryrun else ''
        print("\n==== Summary {0}====".format(note))
        print("%-35s %s" % ("Snapshot tags replicated:", self.count_propagated_tags['snap']))
        print("%-35s %s" % ("Volume tags replicated:", self.count_propagated_tags['vol']))
        print("%-35s %s" % ("Snapshots tagged:", self.count_tagged_resources['snap']))
        print("%-35s %s" % ("Volumes tagged:", self.count_tagged_resources['vol']))
        print("See %s for detailed report. " % (csv_filename) if do_report else '')

    def do_ami_tagging(self, desired_tags, do_tag_untagged, stats_only, dryrun, do_report):
        untagged_amis = list(self.get_untagged_amis(self.owner_account_id, desired_tags))

        self.print("%-35s %s" % ("Account Id:", self.owner_account_id))
        self.print("%-35s %s" % ("Region:", self.region))
        self.print("%-35s %s" % ("Tags to replicate:", ', '.join(desired_tags)))
        self.print("%-35s %s" % ("AMIs to process (untagged):", len(untagged_amis)))

        if stats_only:
            return True

        if do_report:
            # TODODODODODOD
            pass

        for idx, ami_id in enumerate(untagged_amis):
            print("idx - %d || ami-id - %s" % (idx, ami_id))
            ami = self.ec2.Image(ami_id)
            ami_details = self.get_ami_details(ami)

            extracted_tags = {}
            tags_for_ami = {}

            # Enumerating snapshots with an intent to find desired tags
            for snapshot_id in ami_details['snapshots']:
                snap = self.ec2.Snapshot(snapshot_id)
                snap_details = self.get_snapshot_details(snap)
                extracted_tags = self.extract_untagged(snap_details, ami_details, desired_tags)
                tags_for_ami = dict(extracted_tags.items() + tags_for_ami.items())
                if tags_for_ami.keys() == desired_tags:
                    break

            if tags_for_ami:
                if tags_for_ami.keys() == desired_tags:
                    # We found all tags
                    print('All tags for ami - %s were found: %s' % (ami.image_id, tags_for_ami))
                else:
                    print('Some tags for ami - %s were found: %s' % (ami.image_id, tags_for_ami))
            else:
                print('No desired tags was found in associated snapshots')


def main():
    mode, generic_params, mode_params = parse_arguments()
    profile, region = generic_params

    tagging = TagReplicator()
    tagging.connect(profile, region)

    if mode == "snapshot_mode":
        tags_list, do_tag_untagged, ami_lookup, stats_only, dryrun, report = mode_params
        print("mode - %s, mode_params - %s" % (mode, mode_params))
        tagging.do_snapshot_tagging(tags_list, dryrun, stats_only, ami_lookup, report, do_tag_untagged)
    elif mode == "ami_mode":
        tags_list, do_tag_untagged, stats_only, dryrun, report = mode_params
        print("mode - %s, mode_params - %s" % (mode, mode_params))
        tagging.do_ami_tagging(tags_list, do_tag_untagged, stats_only, dryrun, report)


def lambda_handler(event, context):
    # TOODOODODO FIX FOR  AMI_MODE
    env_region = os.environ.get('REGION', 'us-east-1')
    env_dryrun = False if os.environ.get('DRYRUN', False) in ['False', False, 'No'] else True
    env_ami_lookup = False if os.environ.get('AMI_LOOKUP', False) in ['False', False, 'No'] else True
    env_tags = os.environ['TAGS'].split(',')

    if not env_tags:
        print('No tags specified')
        return

    tagging = TagReplicator()
    tagging.connect(profile=None, region=env_region)
    tagging.do_snapshot_tagging(desired_tags=env_tags, dryrun=env_dryrun, stats_only=False,
                                ami_lookup=env_ami_lookup, do_report=False, do_tag_untagged='')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('User break. Finishing..')
        sys.exit(1)
    # except Exception as e:
    #     print(e)


# An error occurred (RequestLimitExceeded) when calling the DescribeSnapshots operation (reached max retries: 4): Request limit exceeded.: ClientError
# Traceback (most recent call last):
#   File "/var/task/tagreplicator.py", line 382, in lambda_handler
#     tagging.do_snapshot_tagging(desired_tags=env_tags, dryrun=env_dryrun, stats_only=False, ami_lookup=env_ami_lookup, do_report=False)
#   File "/var/task/tagreplicator.py", line 270, in do_snapshot_tagging
#     snap_details = self.get_snapshot_details(snap)
#   File "/var/task/tagreplicator.py", line 200, in get_snapshot_details
#     snap_tags = {s['Key']: s['Value'] for s in snap.tags} if snap.tags else {}
#   File "/var/runtime/boto3/resources/factory.py", line 339, in property_loader
#     self.load()
#   File "/var/runtime/boto3/resources/factory.py", line 505, in do_action
#     response = action(self, *args, **kwargs)
#   File "/var/runtime/boto3/resources/action.py", line 83, in __call__
#     response = getattr(parent.meta.client, operation_name)(**params)
#   File "/var/runtime/botocore/client.py", line 312, in _api_call
#     return self._make_api_call(operation_name, kwargs)
#   File "/var/runtime/botocore/client.py", line 601, in _make_api_call
#     raise error_class(parsed_response, operation_name)
# ClientError: An error occurred (RequestLimitExceeded) when calling the DescribeSnapshots operation (reached max retries: 4): Request limit exceeded.