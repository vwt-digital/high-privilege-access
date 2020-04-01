import sys
import json
import os
from git import Repo

import googleapiclient.discovery
from oauth2client.client import GoogleCredentials


def kms_get_policy(project_id, location_id, key_ring_id):
    credentials = GoogleCredentials.get_application_default()
    service = googleapiclient.discovery.build('cloudkms', 'v1', credentials=credentials)

    keyring = 'projects/{}/locations/{}/keyRings/{}'.format(project_id, location_id, key_ring_id)
    policy = service.projects().locations().keyRings().getIamPolicy(resource=keyring).execute()

    print(policy)
    return policy


def kms_modify_policy_add_member(policy, role, member):
    bindings = []
    if 'bindings' in policy.keys():
        bindings = policy['bindings']
    members = []
    members.append(member)
    new_binding = dict()
    new_binding['role'] = role
    new_binding['members'] = members
    bindings.append(new_binding)
    policy['bindings'] = bindings

    print(policy)
    return policy


def kms_set_policy(project_id, location_id, key_ring_id, new_policy):
    credentials = GoogleCredentials.get_application_default()
    service = googleapiclient.discovery.build('cloudkms', 'v1', credentials=credentials)

    keyring = 'projects/{}/locations/{}/keyRings/{}'.format(project_id, location_id, key_ring_id)
    policy = service.projects().locations().keyRings().setIamPolicy(resource=keyring, body={'policy': new_policy}).execute()

    print(policy)
    return policy


def get_policy(project_id):
    """Gets IAM policy for a project."""
    credentials = GoogleCredentials.get_application_default()
    service = googleapiclient.discovery.build('cloudresourcemanager', 'v1', credentials=credentials)

    policy = service.projects().getIamPolicy(resource=project_id, body={}).execute()
    print(policy)
    return policy


def modify_policy_add_member(policy, role, member):
    """Adds a new member to a role binding."""

    binding = next(b for b in policy['bindings'] if b['role'] == role)
    binding['members'].append(member)
    print(binding)
    return policy


def set_policy(project_id, policy):
    """Sets IAM policy for a project."""

    credentials = GoogleCredentials.get_application_default()
    service = googleapiclient.discovery.build('cloudresourcemanager', 'v1', credentials=credentials)

    policy = service.projects().setIamPolicy(resource=project_id, body={'policy': policy}).execute()
    print(policy)
    return policy


if len(sys.argv) < 2:
    print("Insuffcient command line params")
    sys.exit()

project_id = sys.argv[1]

if not os.path.isdir('config/{}'.format(project_id)):
    print("Directory with requests not found")
    sys.exit()

# Get the last commit
repo = Repo('')
last_commit = list(repo.iter_commits(paths='config/{}'.format(project_id)))[0]

for request_file, v in last_commit.stats.files.items():
    if request_file.find('config/{}'.format(project_id)) != -1:
        with open(request_file) as json_file:
            hpa_request = json.load(json_file)

        print(hpa_request)

        if 'operational_access' in hpa_request:
            oa = hpa_request['operational_access'][0]

            if 'odrlPolicy' in oa:
                policy = oa['odrlPolicy']
                for permission in policy['permission']:
                    print(permission)
                    if 'cloudkms' in permission['action']:
                        print("Read")
                        kms_iam_policy = kms_get_policy(permission['target'], permission['location'], permission['keyring'])
                        print("Change")
                        new_iam_policy = kms_modify_policy_add_member(kms_iam_policy, permission['action'], permission['assignee'])
                        print("Write")
                        kms_set_policy(permission['target'], permission['location'], permission['keyring'], new_iam_policy)
                    else:
                        print("Read")
                        iam_policy = get_policy(permission['target'])
                        print("Change")
                        new_iam_policy = modify_policy_add_member(iam_policy, permission['action'], permission['assignee'])
                        print("Write")
                        set_policy(permission['target'], new_iam_policy)
