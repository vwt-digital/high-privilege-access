import sys
import time
import googleapiclient.discovery
from oauth2client.client import GoogleCredentials


def get_policy(project_id):
    """Gets IAM policy for a project."""
    credentials = GoogleCredentials.get_application_default()
    service = googleapiclient.discovery.build('cloudresourcemanager', 'v1', credentials=credentials, cache_discovery=False)
    policy = service.projects().getIamPolicy(resource=project_id, body={}).execute()
    print(policy)
    return policy


def modify_policy_remove_member(policy, role, member):
    """Removes a  member from a role binding."""

    binding = next(b for b in policy['bindings'] if b['role'] == role)
    if 'members' in binding and member in binding['members']:
        binding['members'].remove(member)
    print(binding)
    return policy


def set_policy(project_id, policy):
    """Sets IAM policy for a project."""

    credentials = GoogleCredentials.get_application_default()
    service = googleapiclient.discovery.build('cloudresourcemanager', 'v1', credentials=credentials, cache_discovery=False)

    policy = service.projects().setIamPolicy(resource=project_id, body={'policy': policy}).execute()
    print(policy)
    return policy


def update_cloudkms_policy(projectId):
    credentials = GoogleCredentials.get_application_default()

    kms_service = googleapiclient.discovery.build('cloudkms', 'v1', credentials=credentials)
    project = 'projects/{}'.format(projectId)
    locations = kms_service.projects().locations().list(name=project).execute()

    for location in locations['locations']:
        keyrings = kms_service.projects().locations().keyRings().list(parent=location['name']).execute()

        if 'keyRings' in keyrings:
            for keyRing in keyrings['keyRings']:

                kms_policy = kms_service.projects().locations().keyRings().getIamPolicy(resource=keyRing['name']).execute()
                kms_policy_updated = False
                if 'bindings' in kms_policy:
                    for binding in kms_policy['bindings']:
                        if 'members' in binding:
                            for member in binding['members']:
                                if member.startswith('user'):
                                    print('Remove member {} from policy {}'.format(member, kms_policy))
                                    modify_policy_remove_member(kms_policy, binding['role'], member)
                                    kms_policy_updated = True
                if kms_policy_updated:
                    print(kms_service.projects().locations().keyRings()
                                     .setIamPolicy(resource=keyRing['name'], body={'policy': kms_policy}).execute())


def update_iam_policy(projectId):
    iam_policy = get_policy(projectId)
    modified = False

    for binding in iam_policy['bindings']:
        for member in reversed(binding['members']):
            if 'user:' in member:
                modified = True
                iam_policy = modify_policy_remove_member(iam_policy, binding['role'], member)
                print("Removed [{}],[{}]".format(member, binding['role']))

    if modified:
        print("New Policy {}".format(iam_policy))
        set_policy(pr['projectId'], iam_policy)


if len(sys.argv) > 1:
    parent_id = sys.argv[1]

    credentials = GoogleCredentials.get_application_default()
    service = googleapiclient.discovery.build('cloudresourcemanager', 'v1', credentials=credentials)

    request = service.projects().list(filter="parent.id={} AND lifecycleState:ACTIVE".format(parent_id))

    while request is not None:
        response = request.execute()

        for pr in response.get('projects', []):
            update_iam_policy(pr['projectId'])
            update_cloudkms_policy(pr['projectId'])
            time.sleep(2)

            request = service.projects().list_next(previous_request=request, previous_response=response)
