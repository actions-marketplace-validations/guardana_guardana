-- A run id names one run within one project and one environment, so a run a pinned
-- key stored never answers as a duplicate for another environment, and the reply
-- never tells one environment's key what another holds. `coalesce` because two
-- nulls are distinct in a unique index, and unlabelled runs are one environment.
drop index if exists submissions_project_run_idx;

create unique index submissions_project_environment_run_idx
    on submissions (project_id, coalesce(environment, ''), run_id) where run_id is not null;
