# Release checklist

## Cutting a release

1. Merge the change to main through a pull request.
2. Push the tag (for example `v1.2.3`) on a commit that is on main.
3. Dispatch the Release workflow from main (Actions, Release, Run workflow,
   branch main) with the tag as its input. No tag push publishes anything.

## Repository settings (the checker cannot see these)

These are load-bearing. The workflow's own checks are read from whichever
branch it is dispatched from, so anyone with write access can dispatch a
weakened copy from another branch. Only these settings stop that.

- Environment `release`: required reviewers, and deployment branches limited
  to `main`.
- Branch protection on `main`: pull request and passing checks required.
- Tag ruleset: only the maintainers may create, move or delete release tags.
- Tag ruleset pattern: `v*.*.*`
- Tag name check: `^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$`
