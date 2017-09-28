# Replicates tags to snapshots and volumes
# Dmitry Aliev (c)

# TODO
# Volumes not exist stat + CSV status
# No tags neither at volume nor instance + CSV status
# AMI tag source

from __future__ import print_function
import boto3
from botocore.exceptions import ClientError
from collections import Counter
import re
import os
import csv
import sys
import argparse
from datetime import datetime

def parse_arguments():
    REGION = 'us-east-1'
    PROFILE = None
    parser = argparse.ArgumentParser(description="""
Cost tag replicator. Scans for <tags> untagged snapshots and tags snapshot with volume/instance/ami tag.
""")

    parser.add_argument("--profile", required=False, default=PROFILE, type=str,
                        help="awscli profile to use")
    parser.add_argument("--region", required=False, default=REGION, type=str,
                        help="AWS region (us-east-1 by default)")
    parser.add_argument("--tags", action='store', type=str, required=True,
                        help="List of tags to replicate, separated by comma, e.g Owner,cost (case sensitive")
    parser.add_argument("--stats-only", action="store_true", default=False,
                        help="Print stats on snapshots total vs cost untagged and exit")
    parser.add_argument("--report", action="store_true", default=False,
                        help="Generate csv report")
    parser.add_argument("--dry-run", action="store_true", default=False,
                        help="No actual tagging. Could be used with --report")
    args = parser.parse_args()

    tags_list = args.tags.split(',')
    profile = args.profile
    region = args.region
    stats_only = args.stats_only
    dryrun = args.dry_run
    report = args.report

    return (tags_list, profile, region, stats_only, dryrun, report)


class TagReplicator:

    def __init__(self):
        self.ec2 = None

        self.profile = None
        self.region = 'us-east-1'
        # self.stats_only = False
        # self.dryrun = False
        # self.report = False

        self.owner_account_id = ''
        self.count_tagged_resources = Counter()
        self.count_propagated_tags = Counter()

        self.start_time = None

    def volume_exists(self, id):
        try:
            self.ec2.Volume(id).size
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidVolume.NotFound':
                return False
            else:
                raise e
        return True

    def tag_resource(self, resource, key, value, dryrun):
        prefix = resource.id.split('-')[0]
        self.count_propagated_tags[prefix] += 1
        if dryrun:
            return
        resource.create_tags(
            Tags=[
                {
                    'Key': key,
                    'Value': value
                },
            ]
        )

    def tag_resource_from(self, src_r, src_details, dst_r, dst_details, tags, dryrun=False):
        tags_copied = {}
        for dtag in tags:
            if src_details['tags'].get(dtag):
                if not dst_details['tags'].get(dtag):
                    self.print("Tagging {dst} with tag:{key}={value} from {src} {note}".format(
                        src=src_details['id'],
                        dst=dst_details['id'],
                        key=dtag,
                        value=src_details['tags'].get(dtag),
                        note='(dry run)' if dryrun else '')
                    )
                    self.tag_resource(dst_r, dtag, src_details['tags'].get(dtag), dryrun)
                    tags_copied[dtag] = src_details['tags'].get(dtag)
        return tags_copied

    def get_tag(self, details, key, default=''):
        if details.get('tags'):
            return details.get('tags').get(key, default)

    def connect(self, profile, region):
        self.start_time = datetime.now()
        # TODO: Exception handling, Return tuple (true/false, error message)
        session = boto3.Session(profile_name=profile, region_name=region)
        self.ec2 = session.resource('ec2')

        try:
            self.owner_account_id = session.client('sts').get_caller_identity()['Account']
        except ClientError as e:
            raise e
        return True

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

    def get_snapshot_details(self, snap):
        # TODO: Check if snapshot exists ??
        snap_tags = {s['Key']: s['Value'] for s in snap.tags} if snap.tags else {}
        description = snap.description
        snap_details = {'id': snap.id,
                        'volume_id': snap.volume_id,
                        'description': snap.description,
                        'volume_size': snap.volume_size,
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

    def do_tagging(self, desired_tags, dryrun, stats_only, do_report):
        # TODO
        # Rework Report for multiple tags

        untagged_snapshots = self.get_untagged_snapshots(self.owner_account_id, desired_tags)

        self.print("%-35s %s" % ("Account Id:", self.owner_account_id))
        self.print("%-35s %s" % ("Region:", self.region))
        self.print("%-35s %s" % ("Tags to replicate:", ', '.join(desired_tags)))
        self.print("%-35s %s" % ("Snapshots to process (untagged):", len(untagged_snapshots)))

        if stats_only:
            return True

        if do_report:
            csv_filename = "{0}_{1}_{2}".format(self.owner_account_id, self.region, "untagged_snapshots_.csv")
            csv_file = open(csv_filename, 'w')
            csv_out = csv.writer(csv_file)

        header_row = ['SnapshotId']
        header_row += ['snaptag: ' + tag for tag in desired_tags]
        header_row += ['SnapshotDescription', 'VolumeId', 'VolumeSize']
        header_row += ['voltag: ' + tag for tag in desired_tags]
        header_row += ['InstanceId', 'InstState']
        header_row += ['instancetag: ' + tag for tag in desired_tags]

        if do_report:
            csv_out.writerow(header_row)

        for idx, snapshot_id in enumerate(untagged_snapshots):
            snap_tagged = vol_tagged = {}

            snap = self.ec2.Snapshot(snapshot_id)
            snap_details = self.get_snapshot_details(snap)
            volume = self.ec2.Volume(snap_details['volume_id'])
            volume_details = self.get_volume_details(volume)
            instance = None
            instance_details = {}

            # 1 gather tag for each entity
            # tags_for_volume
            # tags_for_snapshot
            #
            # 2 then actual tag
            if self.volume_exists(snap_details['volume_id']):
                # Snapshot refers to existing volume | # Update tag info to avoid second tagging

                snap_tagged = self.tag_resource_from(volume, volume_details, snap, snap_details, desired_tags, dryrun=dryrun)
                snap_details['tags'] = dict(snap_details['tags'].items() + snap_tagged.items())

                #!!! Add AMI lookup
                if volume.attachments and set(volume_details['tags'].keys()) != set(desired_tags):
                    # Volume has instance attached and volume has some desired tags omitted. So try to complete with instance tags.
                    instance = self.ec2.Instance(volume.attachments[0]['InstanceId'])
                    instance_details = self.get_instance_details(instance)

                    # if do_volume_tagging then
                    vol_tagged = self.tag_resource_from(instance, instance_details, volume, volume_details, desired_tags, dryrun=dryrun)
                    volume_details['tags'] = dict(volume_details['tags'].items() + vol_tagged.items())



                    snap_tagged = self.tag_resource_from(instance, instance_details, snap, snap_details, desired_tags, dryrun=dryrun)
                    snap_details['tags'] = dict(snap_details['tags'].items() + snap_tagged.items())


            if len(vol_tagged):
                self.count_tagged_resources['vol'] += 1
            if len(snap_tagged):
                self.count_tagged_resources['snap'] += 1

            # Assemble row for csv
            data_row = [snap_details['id']]
            data_row += [self.get_tag(snap_details, tag) for tag in desired_tags]
            data_row += [snap_details['description'],
                         volume_details.get('id'),
                         snap_details.get('volume_size')
                         ]
            data_row += [self.get_tag(volume_details, tag) for tag in desired_tags]
            data_row += [instance_details.get('id'),
                         instance_details.get('state')
                         ]
            data_row += [self.get_tag(instance_details, tag) for tag in desired_tags]

            if do_report:
                csv_out.writerow(data_row)
        if do_report:
            csv_file.close()

        note = "(forecast)" if dryrun else ''
        self.print("\n==== Summary {0}====".format(note))
        self.print("%-35s %s" % ("Snapshot tags replicated:", self.count_propagated_tags['snap']))
        self.print("%-35s %s" % ("Volume tags replicated:", self.count_propagated_tags['vol']))
        self.print("%-35s %s" % ("Snapshots tagged:", self.count_tagged_resources['snap']))
        self.print("%-35s %s" % ("Volumes tagged:", self.count_tagged_resources['vol']))
        self.print("See %s for detailed report. " % (csv_filename) if do_report else '')

        #self.print("%-35s %s" % ("Volumes not exist(!!!!!!):", volumes_not_exist_count))
        #self.print("%-35s %s" % ("No tags neither at volume nor instance :", no_one_has_tags_count))


def main():
    tags_list, profile, region, stats_only, dryrun, report = parse_arguments()
    tagging = TagReplicator()
    tagging.connect(profile, region)
    tagging.do_tagging(tags_list, dryrun, stats_only, report)


def lambda_handler():
    env_region = os.environ.get('REGION','us-east-1')
    env_dryrun = False if os.environ.get('DRYRUN', False) in ['False', False, 'No'] else True
    env_tags = os.environ['TAGS'].split(',')
    if not env_tags:
        print('No tags specified')
        return

    tagging = TagReplicator()
    tagging.connect(profile=None, region=env_region)
    tagging.do_tagging(tags_list=env_tags, dryrun=env_dryrun, stats_only=False, report=False)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('User break. Finishing..')
        sys.exit(1)
#    except Exception as e:
#        print(e)
