-- Refused by the unique index while two environments hold one run id: the rollback
-- stops rather than deleting either run.
drop index if exists submissions_project_environment_run_idx;

create unique index submissions_project_run_idx
    on submissions (project_id, run_id) where run_id is not null;
