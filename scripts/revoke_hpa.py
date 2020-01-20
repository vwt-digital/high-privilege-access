import sys
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


if len(sys.argv) > 1:
    parent_id = sys.argv[1]

    credentials = GoogleCredentials.get_application_default()
    service = googleapiclient.discovery.build('cloudresourcemanager', 'v1', credentials=credentials)

    request = service.projects().list(filter="parent.id={}".format(parent_id))

    while request is not None:
        response = request.execute()

        for pr in response.get('projects', []):
            print(pr['projectId'])

            policy = get_policy(pr['projectId'])
            modified = False

            for binding in policy['bindings']:
                for member in reversed(binding['members']):
                    if 'user:' in member:
                        modified = True
                        policy = modify_policy_remove_member(policy, binding['role'], member)
                        print("Removed [{}],[{}]".format(member, binding['role']))

            if modified:
                print("New Policy {}".format(policy))
                set_policy(pr['projectId'], policy)

            request = service.projects().list_next(previous_request=request, previous_response=response)
