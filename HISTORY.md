Changelog
=========


(unreleased)
------------
- Add FastAPI-native Authorize dependency for route authorization and
  update documentation. [Sébastien]
- Refactor CI/CD workflows and update dependencies for improved
  compatibility and security. [Sébastien]
- Remove setup.py and test requirements files to streamline project
  structure. [Sébastien]
- Enhance token validation and authorization handling in Azure AD
  integration. [Sébastien]

  - Added detailed token validation rules in README.md.
  - Refactored token decoding logic to enforce audience and issuer checks.
  - Introduced support for app-only tokens with roles in permission validation.
  - Updated AzureAdSettings to allow configuration of token permission requirements.
  - Improved test coverage for token validation and authorization scenarios.
- Refactor code for improved type handling and error checking across
  multiple modules. [Sébastien]
- Refactor token decoding and Azure AD settings for improved clarity and
  error handling. [Sébastien]
- Enhance JWT handling and testing: - Update settings for Python
  analysis and testing in VSCode. - Refactor AadDiscoverKey for improved
  key management and caching. - Modify aad_helpers to streamline token
  decoding and error handling. - Update AadUser claims type to use Dict
  for better flexibility. - Revise requirements to remove unused
  libraries and ensure compatibility. - Improve test coverage for token
  decoding and claims validation. - Update README with clearer
  instructions on mocking Azure AD responses. [Sébastien]


1.1.5 (2024-11-26)
------------------
- Release: version 1.1.5 🚀 [Sebastien Pertus]
- Remove requirements version. Update aad_options. [Sebastien Pertus]
- Update README.md. [Dor Lugasi-Gal]
- Release: version 1.1.4 🚀 [Sebastien Pertus]


1.1.4 (2023-09-12)
------------------
- Release: version 1.1.4 🚀 [Sebastien Pertus]
- Merge pull request #11 from Mimetis/add-optional-extra-allowed.
  [Sébastien Pertus]

  add extra
- Add flake8 / black extensions. [Sebastien Pertus]
- Fix lint. [Sebastien Pertus]
- Add extra. [Sebastien Pertus]


1.1.3 (2023-08-21)
------------------
- Release: version 1.1.3 🚀 [Sebastien Pertus]
- Merge pull request #10 from Mimetis/spertus/specify-frameworks-
  version. [Sébastien Pertus]

  Do not specify strict versions
- Removed uncessary env vars for test. [Sebastien Pertus]
- Reloved unecessary test env variable. [Sebastien Pertus]
- Make Field as Optional. [Sebastien Pertus]
- Reformat. [Sebastien Pertus]
- Replacing None with empty string. [Sebastien Pertus]
- Resolve issue with basesettings. [Sebastien Pertus]
- Update requirements of fastapi to include all dependencies. [Sebastien
  Pertus]
- Do not specify strict versions. [Sebastien Pertus]


1.1.2 (2023-07-20)
------------------
- Release: version 1.1.2 🚀 [Dor Lugasi-Gal]
- Py.exe. [Dor Lugasi-Gal]
- Remove --user. [Dor Lugasi-Gal]
- Make test to run on windows. [Dor Lugasi-Gal]
- Pythonpath fix. [Dor Lugasi-Gal]


1.1.1 (2023-07-20)
------------------
- Release: version 1.1.1 🚀 [Dor Lugasi-Gal]
- Release: version ${TAG} ≡ƒÜÇ. [Dor Lugasi-Gal]
- Added multidict. [Dor Lugasi-Gal]


1.1.0 (2023-04-03)
------------------
- Release: version 1.1.0 🚀 [Dor Lugasi-Gal]
- Added role_requirements.Any\All behaviour to the authorize decorator
  (#7) [Dor Lugasi-Gal]

  * added role_requirements.Any\All behavior to the authorized decorator
  * Added some docstrings
  * formatting
  * merge tests with parametrize
  * readme update


1.0.5 (2023-03-22)
------------------
- Release: version 1.0.5 🚀 [Dor Lugasi-Gal]
- Merge pull request #6 from Mimetis/dorlu/fix/pipe-options-to-bearer-
  backend. [Dor Lugasi-Gal]

  pipe options from bearer backend to ensure_user_from_token
- Removed cache manager. [Dor Lugasi-Gal]
- Merge remote-tracking branch 'origin/master' into dorlu/fix/pipe-
  options-to-bearer-backend. [Dor Lugasi-Gal]

  # Conflicts:
  #	aad_fastapi/aad_cache_manager.py
- Formatting. [Dor Lugasi-Gal]
- Pipe options from bearer backend to ensure_user_from_token. [Dor
  Lugasi-Gal]


1.0.4 (2023-03-13)
------------------
- Release: version 1.0.4 🚀 [root]
- Release: version ${TAG} ≡ƒÜÇ. [Dor Lugasi]
- Merge pull request #4 from Mimetis/dorlu/fix/remove-redundant-code.
  [Dor Lugasi-Gal]

  Dorlu/fix/remove redundant code
- Dont need reach. [Dor Lugasi-Gal]
- Small change to check PR comment. [Dor Lugasi-Gal]
- Codecov.yml file (to show report on the PR as a comment) [Dor Lugasi-
  Gal]
- Codecov.yml file (to show report on the PR as a comment) [Dor Lugasi-
  Gal]
- Lint. [Dor Lugasi-Gal]
- Readme changes. [Dor Lugasi-Gal]
- Minor code changes and remove redundant cache manager and certificate
  files. [Dor Lugasi-Gal]


1.0.3 (2023-03-08)
------------------
- Release: version 1.0.3 🚀 [Dor Lugasi-Gal]
- Release: version 1.0.3 🚀 [Dor Lugasi-Gal]
- Release: version 1.0.3 🚀 [Dor Lugasi-Gal]
- Merge branch 'master' of https://github.com/Mimetis/aad_fastapi. [Dor
  Lugasi-Gal]
- Update release.yml. [Dor Lugasi-Gal]
- Release: version 1.0.3 🚀 [Dor Lugasi-Gal]
- Release: version 1.0.3 🚀 [Dor Lugasi-Gal]
- Upload to codecov only once. [Dor Lugasi-Gal]
- Trigger on master andadd versions to python version matrix. [Dor
  Lugasi-Gal]
- Merge pull request #3 from Mimetis/dorlu/restructure-code. [Sébastien
  Pertus]

  New Structure for code
- Very basic dev container. [Dor Lugasi-Gal]
- Update VERSION. [Dor Lugasi-Gal]
- Update CONTRIBUTING.md. [Dor Lugasi-Gal]
- Update HISTORY.md. [Dor Lugasi-Gal]
- Update FUNDING.yml. [Dor Lugasi-Gal]
- Adding dev container and vscode configuration again. [Dor Lugasi-Gal]
- New structure. [Dor Lugasi-Gal]
- Merge pull request #2 from Mimetis/dorlu/feature/remove-redundant-
  backend-logic. [Dor Lugasi-Gal]

  🔥 remove redundant backend logic
- Update sample/api/main.py. [Dor Lugasi-Gal, Sharon Hart]
- Update tests/test_oauth2_scheme.py. [Dor Lugasi-Gal, Sharon Hart]
- Modified sample readme. [Dor Lugasi-Gal]
- Merge remote-tracking branch 'origin/dorlu/feature/remove-redundant-
  backend-logic' into dorlu/feature/remove-redundant-backend-logic. [Dor
  Lugasi-Gal]
- Update main.py. [Dor Lugasi-Gal]
- Fixed source root. [Dor Lugasi-Gal]
- :fire: removed redundant aad_client and its dependencies and usages.
  [Dor Lugasi-Gal]
- :fire: removed redundant aad_client and its dependencies and usages.
  [Dor Lugasi-Gal]
- Merge remote-tracking branch 'origin/master' [Dor Lugasi-Gal]

  # Conflicts:
  #	src/pyproject.toml
- Update pyproject.toml. [Dor Lugasi-Gal]
- Update pyproject.toml. [Dor Lugasi-Gal]
- Update pyproj. [Dor Lugasi-Gal]
- Fix readme location. [Dor Lugasi-Gal]
- Merge pull request #1 from dorlugasigal/dorlu/fix/packaging-moved-to-
  pyproject-toml. [Sébastien Pertus]

  fixed packaging and set version to 1.0.0
- Update aad_token.py. [Dor Lugasi-Gal]
- Fixed aad_token file. [Dor Lugasi-Gal]
- Fixed folder structure again. [Dor Lugasi-Gal]
- Fixed and bumped version to 1.0.0. [Dor Lugasi-Gal]
- Change to aad_fastapi. [Sebastien Pertus]
- Change to aad_fastapi. [Sebastien Pertus]
- Completing readme.md file. [Sebastien Pertus]
- Add readme file. [Sebastien Pertus]
- Fixes. [Sebastien Pertus]
- Add clean flask session. [Sebastien Pertus]
- Fix secret. [Sebastien Pertus]
- Fix issues depending on two app registrations. [Sebastien Pertus]
- Inprogress. [Sebastien Pertus]
- Add launch.json. [Sebastien Pertus]
- Correct ssh path. [Sebastien Pertus]
- Add first commit. [Sebastien Pertus]


