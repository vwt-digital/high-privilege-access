import git
import json
import argparse
import logging

from pprint import pformat
from googleapiclient import discovery
from oauth2client.client import GoogleCredentials

logging.basicConfig(level=logging.INFO, format='%(levelname)7s: %(message)s')


def get_kms_policy(service, project_id, location_id, key_ring_id):
    """Gets iam policy for a keyring."""

    keyring = 'projects/{}/locations/{}/keyRings/{}'.format(
        project_id,
        location_id,
        key_ring_id)

    policy = service.projects().locations().keyRings().getIamPolicy(
        resource=keyring).execute()

    return policy


def set_kms_policy(service, project_id, location_id, key_ring_id, policy):
    """Sets iam policy for a keyring."""

    keyring = 'projects/{}/locations/{}/keyRings/{}'.format(
        project_id,
        location_id,
        key_ring_id)

    policy = service.projects().locations().keyRings().setIamPolicy(
        resource=keyring,
        body={'policy': policy}).execute()

    return policy


def modify_kms_policy(policy, role, member):
    """Adds a new member to a kms role binding."""

    bindings = []
    if 'bindings' in policy.keys():
        bindings = policy['bindings']
    members = [member]

    new_binding = dict()
    new_binding['role'] = role
    new_binding['members'] = members
    bindings.append(new_binding)
    policy['bindings'] = bindings

    return policy


def get_stg_policy(service, bucket):
    """Gets IAM policy for a project."""

    policy = service.buckets().getIamPolicy(
        bucket=bucket.replace('gs://', '')).execute()

    return policy


def set_stg_policy(service, bucket, policy):
    """Sets IAM policy for a project."""

    policy = service.buckets().setIamPolicy(
        bucket=bucket.replace('gs://', ''),
        body=policy).execute()

    return policy


def modify_stg_policy(policy, role, member):
    """Adds a new member to a storage role binding."""

    binding = next(b for b in policy['bindings'] if b['role'] == role)
    binding['members'].append(member)

    return policy


def get_iam_policy(service, project_id):
    """Gets IAM policy for a project."""

    policy = service.projects().getIamPolicy(
        resource=project_id,
        body={}).execute()

    return policy


def set_iam_policy(service, project_id, policy):
    """Sets IAM policy for a project."""

    policy = service.projects().setIamPolicy(
        resource=project_id,
        body={'policy': policy}).execute()

    return policy


def modify_iam_policy(policy, role, member):
    """Adds a new member to a role binding."""

    binding = next(b for b in policy['bindings'] if b['role'] == role)
    binding['members'].append(member)

    return policy


def make_service(service):
    """Makes a service googleapiclient service."""

    credentials = GoogleCredentials.get_application_default()

    service = discovery.build(
        service, 'v1',
        credentials=credentials,
        cache_discovery=False)

    return service


def get_last_commit(project_id):
    """Returns commit info for the last commmit in the current repo."""

    repo = git.Repo('')
    last_commit = list(repo.iter_commits(paths='config/{}'.format(project_id)))[0]

    return last_commit


def parse_args():
    """A simple function to parse command line arguments."""

    parser = argparse.ArgumentParser(description='Grant high privilege access requests')
    parser.add_argument('-p', '--project-id',
                        required=True,
                        help='name of the GCP project')
    return parser.parse_args()


def main(args):

    last_commit = get_last_commit(args.project_id)

    for file, value in last_commit.stats.files.items():

        logging.info('Changed file: {}'.format(file))

        with open(file) as json_file:
            hpa_request = json.load(json_file)

        logging.info('Processing hpa request:')
        logging.info(pformat(hpa_request))

        for access_request in hpa_request.get('operational_access', []):

            for permission in access_request.get('odrlPolicy', {}).get('permission', []):

                if 'cloudkms' in permission['action']:

                    kms_service = make_service('cloudkms')
                    kms_policy = get_kms_policy(kms_service, permission['target'], permission['location'], permission['keyring'])
                    new_kms_policy = modify_kms_policy(kms_policy, permission['action'], permission['assignee'])
                    set_kms_policy(permission['target'], permission['location'], permission['keyring'], new_kms_policy)

                    logging.info('Set new kms policy:')
                    logging.info(pformat(new_kms_policy))

                elif permission['target'].startswith('gs://'):

                    stg_service = make_service('storage')
                    stg_policy = get_stg_policy(stg_service, permission['target'])
                    new_stg_policy = modify_stg_policy(stg_policy, permission['action'], permission['assignee'])
                    set_stg_policy(stg_service, permission['target'], new_stg_policy)

                    logging.info('Set new storage policy:')
                    logging.info(pformat(new_stg_policy))

                else:

                    crm_service = make_service('cloudresourcemanager')
                    iam_policy = get_iam_policy(crm_service, permission['target'])
                    new_iam_policy = modify_iam_policy(iam_policy, permission['action'], permission['assignee'])
                    set_iam_policy(crm_service, permission['target'], new_iam_policy)

                    logging.info('Set new project iam policy:')
                    logging.info(pformat(new_iam_policy))


if __name__ == '__main__':
    main(parse_args())
