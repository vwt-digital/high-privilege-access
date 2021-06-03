import argparse
import json
import logging
import sys
from datetime import datetime, timedelta
from os import path
from pprint import pformat

import git
from googleapiclient import discovery
from oauth2client.client import GoogleCredentials

logging.basicConfig(level=logging.INFO, format="%(levelname)7s: %(message)s")


def get_kms_policy(service, project_id, location_id, key_ring_id):
    """Gets iam policy for a keyring."""

    keyring = "projects/{}/locations/{}/keyRings/{}".format(
        project_id, location_id, key_ring_id
    )

    policy = (
        service.projects()
        .locations()
        .keyRings()
        .getIamPolicy(resource=keyring)
        .execute()
    )

    return policy


def set_kms_policy(service, project_id, location_id, key_ring_id, policy):
    """Sets iam policy for a keyring."""

    keyring = "projects/{}/locations/{}/keyRings/{}".format(
        project_id, location_id, key_ring_id
    )

    policy = (
        service.projects()
        .locations()
        .keyRings()
        .setIamPolicy(resource=keyring, body={"policy": policy})
        .execute()
    )

    return policy


def get_stg_policy(service, bucket):
    """Gets IAM policy for a project."""

    policy = (
        service.buckets().getIamPolicy(bucket=bucket.replace("gs://", "")).execute()
    )

    return policy


def set_stg_policy(service, bucket, policy):
    """Sets IAM policy for a project."""

    policy = (
        service.buckets()
        .setIamPolicy(bucket=bucket.replace("gs://", ""), body=policy)
        .execute()
    )

    return policy


def modify_policy(policy, role, member, condition):
    """Modify policy"""

    bindings = []
    if "bindings" in policy.keys():
        bindings = policy["bindings"]
    members = [member]

    new_binding = dict()
    new_binding["role"] = role
    new_binding["members"] = members
    new_binding["condition"] = condition
    bindings.append(new_binding)
    policy["bindings"] = bindings

    return policy


def get_iam_policy(service, project_id):
    """Gets IAM policy for a project."""

    policy = service.projects().getIamPolicy(resource=project_id, body={}).execute()

    return policy


def set_iam_policy(service, project_id, policy):
    """Sets IAM policy for a project."""

    policy = (
        service.projects()
        .setIamPolicy(resource=project_id, body={"policy": policy})
        .execute()
    )

    return policy


def get_iam_policy_condition(policy_uid):
    expiration_date = (datetime.utcnow() + timedelta(days=1)).strftime(
        "%Y-%m-%dT00:00:00Z"
    )
    condition = {
        "title": f"{policy_uid}-expiry-condition",
        "description": f"IAM expiry condition by end of day for policy {policy_uid}",
        "expression": f"request.time < timestamp('{expiration_date}')",
    }

    return condition


def make_service(service):
    """Makes a service googleapiclient service."""

    credentials = GoogleCredentials.get_application_default()

    service = discovery.build(
        service, "v1", credentials=credentials, cache_discovery=False
    )

    return service


def git_changed_files(project_id):
    """Returns commit info for the last commmit in the current repo."""

    repo = git.Repo("")
    branch = str(repo.active_branch)

    files = []

    if branch == "develop":
        last_commit = list(repo.iter_commits(paths="config/{}".format(project_id)))[0]
        files = [file for file in last_commit.stats.files.keys() if project_id in file]

    elif branch == "master":
        headcommit = repo.head.commit
        while True:
            headcommit = headcommit.parents[0]
            if len(headcommit.parents) != 1:
                break

        last_commits = list(repo.iter_commits(rev="{}..{}".format(headcommit, branch)))

        for commit in last_commits:
            for file in commit.stats.files.keys():
                if project_id in file:
                    files.append(file)

    return list(set(files))


def parse_args():
    """A simple function to parse command line arguments."""

    parser = argparse.ArgumentParser(description="Grant high privilege access requests")
    parser.add_argument(
        "-p", "--project-id", required=True, help="name of the GCP project"
    )
    parser.add_argument(
        "-r",
        "--forbidden-roles",
        required=False,
        help="list of forbidden roles separated by comma",
    )
    return parser.parse_args()


def main(args):

    files = git_changed_files(args.project_id)

    for file in files:

        if not path.exists(file):
            logging.info("File {} does not exist".format(file))
            continue

        logging.info("Changed file: {}".format(file))

        with open(file) as json_file:
            hpa_request = json.load(json_file)

        logging.info("Processing hpa request:")
        logging.info(pformat(hpa_request))

        for access_request in hpa_request.get("operational_access", []):

            for permission in access_request.get("odrlPolicy", {}).get(
                "permission", []
            ):
                policy_uid = access_request["odrlPolicy"].get(
                    "uid", f"{permission['target']}-policy"
                )
                policy_condition = get_iam_policy_condition(policy_uid)

                if args.forbidden_roles and permission[
                    "action"
                ] in args.forbidden_roles.split(","):
                    print(
                        f"\033[91mERROR: Role '{permission['action']}' is a basic role and is forbidden to use, "
                        f"please define either a predefined or custom role. "
                        f"See https://github.com/vwt-digital/high-privilege-access/blob/develop/README.md"
                        f"#basic-roles-alternatives for alternative roles.\033[0m"
                    )
                    sys.exit(1)

                if "cloudkms" in permission["action"]:

                    kms_service = make_service("cloudkms")
                    kms_policy = get_kms_policy(
                        kms_service,
                        permission["target"],
                        permission["location"],
                        permission["keyring"],
                    )
                    new_kms_policy = modify_policy(
                        kms_policy,
                        permission["action"],
                        permission["assignee"],
                        policy_condition,
                    )
                    set_kms_policy(
                        permission["target"],
                        permission["location"],
                        permission["keyring"],
                        new_kms_policy,
                    )

                    logging.info("Set new kms policy bindings:")
                    logging.info(pformat(new_kms_policy))

                elif permission["target"].startswith("gs://"):

                    stg_service = make_service("storage")
                    stg_policy = get_stg_policy(stg_service, permission["target"])
                    new_stg_policy = modify_policy(
                        stg_policy,
                        permission["action"],
                        permission["assignee"],
                        policy_condition,
                    )
                    set_stg_policy(stg_service, permission["target"], new_stg_policy)

                    logging.info("Set new storage policy bindings:")
                    logging.info(pformat(new_stg_policy))

                else:

                    crm_service = make_service("cloudresourcemanager")
                    iam_policy = get_iam_policy(crm_service, permission["target"])
                    new_iam_policy = modify_policy(
                        iam_policy,
                        permission["action"],
                        permission["assignee"],
                        policy_condition,
                    )
                    set_iam_policy(crm_service, permission["target"], new_iam_policy)

                    logging.info("Set new project iam policy bindings:")
                    logging.info(pformat(new_iam_policy.get("bindings")))


if __name__ == "__main__":
    main(parse_args())
