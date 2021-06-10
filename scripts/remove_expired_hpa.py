import re
import sys
import time
from datetime import datetime

import googleapiclient.discovery
from oauth2client.client import GoogleCredentials

policy_version = 3  # See https://cloud.google.com/iam/docs/policies#versions


def get_service(service_name):
    credentials = GoogleCredentials.get_application_default()
    service = googleapiclient.discovery.build(
        service_name, "v1", credentials=credentials, cache_discovery=False
    )

    return service


def modify_policy_remove_member(policy, role, member):
    binding = next(b for b in policy["bindings"] if b["role"] == role)
    if "members" in binding and member in binding["members"]:
        binding["members"].remove(member)

    policy["version"] = policy_version
    return policy


def binding_condition_expired(binding):
    """Get expired timestamp and match against current timestamp"""

    if "expression" in binding.get("condition", {}):
        condition_timestamp = re.search(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", binding["condition"]["expression"]
        ).group()

        if datetime.utcnow() > datetime.strptime(
            condition_timestamp, "%Y-%m-%dT%H:%M:%SZ"
        ):
            return True

    return False


def update_cloudkms_policy(projectId, kms_service):
    project = "projects/{}".format(projectId)
    locations = kms_service.projects().locations().list(name=project).execute()

    for location in locations["locations"]:
        key_rings = (
            kms_service.projects()
            .locations()
            .keyRings()
            .list(parent=location["name"])
            .execute()
        )

        for key_ring in key_rings.get("keyRings", []):
            kms_policy = (
                kms_service.projects()
                .locations()
                .keyRings()
                .getIamPolicy(resource=key_ring["name"])
                .execute()
            )
            kms_policy_updated = False

            for binding in kms_policy.get("bindings", []):
                for member in binding.get("members", []):
                    if member.startswith("user"):
                        print(
                            "Remove member {} from policy {}".format(member, kms_policy)
                        )
                        modify_policy_remove_member(kms_policy, binding["role"], member)
                        kms_policy_updated = True
            if kms_policy_updated:
                print(
                    kms_service.projects()
                    .locations()
                    .keyRings()
                    .setIamPolicy(
                        resource=key_ring["name"], body={"policy": kms_policy}
                    )
                    .execute()
                )


def update_iam_policy(project_id, iam_service):
    iam_policy = (
        iam_service.projects()
        .getIamPolicy(
            resource=project_id,
            body={"options": {"requestedPolicyVersion": policy_version}},
        )
        .execute()
    )
    modified = False

    for binding in iam_policy["bindings"]:
        binding_expired = binding_condition_expired(binding)

        for member in reversed(binding["members"]):
            if "user:" in member and binding_expired:
                modified = True
                iam_policy = modify_policy_remove_member(
                    iam_policy, binding["role"], member
                )
                print("Removed [{}],[{}]".format(member, binding["role"]))

    if modified:
        print("New Policy {}".format(iam_policy))
        iam_service.projects().setIamPolicy(
            resource=project_id, body={"policy": iam_policy}
        ).execute()


def update_bucket_policy(project_id, stg_service):
    bucket_list = stg_service.buckets().list(project=project_id).execute()

    for bucket in bucket_list["items"]:
        stg_policy = stg_service.buckets().getIamPolicy(bucket=bucket["name"]).execute()
        stg_policy_updated = False

        for binding in stg_policy.get("bindings", []):
            for member in binding.get("members", []):
                if member.startswith("user"):
                    print("Remove member {} from policy {}".format(member, stg_policy))
                    modify_policy_remove_member(stg_policy, binding["role"], member)
                    stg_policy_updated = True
        if stg_policy_updated:
            print("New Policy {}".format(stg_policy))
            stg_service.buckets().setIamPolicy(
                bucket=bucket["name"], body=stg_policy
            ).execute()


def main():
    if len(sys.argv) > 1:
        parent_id = sys.argv[1]

        iam_service = get_service("cloudresourcemanager")
        kms_service = get_service("cloudkms")
        stg_service = get_service("storage")

        request = iam_service.projects().list(
            filter="parent.id={} AND lifecycleState:ACTIVE".format(parent_id)
        )

        while request is not None:
            response = request.execute()

            for pr in response.get("projects", []):
                print("Updating iam policy from project [{}]".format(pr["projectId"]))
                update_iam_policy(pr["projectId"], iam_service)

                print(
                    "Updating cloudkms policy from project [{}]".format(pr["projectId"])
                )
                update_cloudkms_policy(pr["projectId"], kms_service)

                print(
                    "Updating bucket policy from project [{}]".format(pr["projectId"])
                )
                update_bucket_policy(pr["projectId"], stg_service)
                time.sleep(2)

                request = iam_service.projects().list_next(
                    previous_request=request, previous_response=response
                )


if __name__ == "__main__":
    # execute only if run as a script
    main()
