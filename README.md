# High Privilege Access request

## Basic Roles alternatives
Due to security reasons, the usage of Basic Roles within a High Privilege Request are forbidden. These roles often have 
too much permission for the purposes.

To make this new implementation a little easier some alternatives have been defined to use when requesting HPA. These 
alternatives are based on common purposes for applying for HPA.

Service | Purpose | Roles
--- | --- | ---
Cloud Build | Trigger a build | `roles/cloudbuild.builds.editor`
Cloud Build | Connect a repository | `roles/cloudbuild.builds.editor`

> Check the [predefined roles](https://cloud.google.com/iam/docs/understanding-roles#predefined_roles) for all GCP roles
