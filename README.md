# Truffle Hog
Searches through git repositories for secrets, digging deep into commit history and branches. This is effective at finding secrets accidentally committed.

## NEW
Trufflehog previously functioned by running entropy checks on git diffs. This functionality still exists, but high signal regex checks have been added, and the ability to surpress entropy checking has also been added.

These features help cut down on noise, and makes the tool easier to shove into a devops pipeline.


```
truffleHog --regex --entropy=False https://github.com/dxa4481/truffleHog.git
```

or

```
truffleHog file:///user/dxa4481/codeprojects/truffleHog/
```

![Example](https://i.imgur.com/YAXndLD.png)

To search a classic directory, use only the path of the directory like

```
truffleHog /user/dxa4481/codeprojects/truffleHog/
```

## Install
From source (clone repo and then):
```
cd trufflehog
python setup.py install
```

## Manual

```
truffleHog <path> [--json] [--start_date <YYYY-MM-DD>] [--end_date <YYYY-MM-DD>] [--gitignore] [--fileignore <path_to_fileignore>] [--keyignore <path_to_keyignore>] [--filewhitelist filepath1[,filpathN]]
```

``path`` is one of the following :
- https://github.com/dxa4481/truffleHog.git (remote git path) : will clone a repository and check the content of Git history (commits)
- file:///user/dxa4481/codeprojects/truffleHog/ (local git path) : will check the content of Git history (commits) from a local Git directory
- /user/dxa4481/codeprojects/truffleHog/ (local path) : will check recursively the content of a directory

``options`` can be :

```
--json
Format results as JSON
```
```
--regex
Use regex for checks
```
```
--entropy=False
Disable entropy checking
```
```
--gitignore
Ignore files listed in .gitignore in analyzed directory/git root directory
```
```
--fileignore <path_to_fileignore>
Ignore files listed in a custom <path_to_fileignore> (.gitignore syntax)
```
```
--keyignore <path_to_keyignore>
Ignore keys listed in a custom <path_to_fkeyignore> (regex syntax). Can be used as an false positive key regexp list
```
```
--filewhitelist filepath1[,filpathN]
Anlyze only file names that matches filepathX (regex syntax supported)
```
```
--start_date YYYY-MM-DD
Limit analysis only to commit strictly newer than the start_date. Applies only to Git history analysis
```
```
--end_date YYYY-MM-DD
Limit analysis only to commit strictly older than the end_date. Applies only to Git history analysis
```
Usage examples :
- ``truffleHog <path> --start_date 2017-01-01`` : look only for commits newer than 2017-01-01 00:00:00
- ``truffleHog <path> --end_date 2017-01-01 --json`` : look only for commits older than 2017-01-01 00:00:00 and print it as JSON
- ``truffleHog <path> --start_date 2017-01-01 --end_date 2017-01-04`` : look only for commits newer than 2017-01-01 00:00:00 AND older than 2017-01-04 00:00:00

## Customizing

Custom regexes can be added to the following file:
```
truffleHog/truffleHog/regexChecks.py
```
Things like subdomain enumeration, s3 bucket detection, and other useful regexes highly custom to the situation can be added.

Feel free to also contribute high signal regexes upstream that you think will benifit the community. Things like Azure keys, Twilio keys, Google Compute keys, are welcome, provided a high signal regex can be constructed.

## How it works
This module will go through the entire commit history of each branch, and check each diff from each commit, and evaluate the shannon entropy for both the base64 char set and hexidecimal char set for every blob of text greater than 20 characters comprised of those character sets in each diff. If at any point a high entropy string >20 characters is detected, it will print to the screen.
